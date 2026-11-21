"""Le vocabulaire commun à tous les modules : une cible, un constat, la convergence, la note."""
from dataclasses import asdict, dataclass, field

CRITIQUE, IMPORTANT, INFO, OK = "CRITIQUE", "IMPORTANT", "INFO", "OK"
ORDRE = {CRITIQUE: 0, IMPORTANT: 1, INFO: 2, OK: 3}
# Points retirés à la note de 100 pour chaque constat.
POIDS = {CRITIQUE: 25, IMPORTANT: 10, INFO: 2, OK: 0}


class ControleImpossible(Exception):
    """Le contrôle n'a pas pu être fait. Il est listé à part, jamais compté comme un défaut."""


@dataclass
class Cible:
    """Ce sur quoi porte le diagnostic. Toujours le client lui-même, jamais un tiers."""
    domaine: str
    societe: str = ""
    pseudos: list = field(default_factory=list)   # pseudos du dirigeant, donnés par lui
    accord_dirigeant: bool = False                # accord écrit pour chercher ses comptes
    reponses: dict = field(default_factory=dict)  # réponses au questionnaire assureur (id -> oui/non)


@dataclass
class Constat:
    bloc: str          # Exposition, Accès, Réseau et postes, Sauvegardes
    niveau: str        # CRITIQUE, IMPORTANT, INFO ou OK
    titre: str         # une ligne, en français de patron
    explication: str   # ce que ça veut dire pour l'entreprise
    correction: str = ""     # quoi faire
    cle: str = ""            # deux constats de même clé portent sur le MÊME problème : on fusionne
    sources: list = field(default_factory=list)  # quel(s) outil(s) l'ont trouvé (gardé pour Anass)
    # Utile au dirigeant mais pas une faille (« site sous WordPress », « page lente ») :
    # affiché dans le rapport, sans retirer de points. Décision d'Anass du 21/11/2026.
    hors_note: bool = False

    def en_dict(self):
        return asdict(self)


def trier(constats):
    return sorted(constats, key=lambda c: ORDRE[c.niveau])


def fusionner(constats):
    """La convergence : plusieurs outils trouvent souvent le même problème. On n'en garde
    qu'un par clé — le plus grave — en réunissant les outils qui l'ont signalé.
    Un constat sans clé n'est jamais fusionné (chaque constat compte)."""
    retenus, par_cle = [], {}
    for constat in constats:
        if not constat.cle:
            retenus.append(constat)
            continue
        garde = par_cle.get(constat.cle)
        if garde is None:
            par_cle[constat.cle] = constat
            retenus.append(constat)
        else:
            for source in constat.sources:
                if source not in garde.sources:
                    garde.sources.append(source)
            # on garde la version la plus grave des deux
            if ORDRE[constat.niveau] < ORDRE[garde.niveau]:
                garde.niveau, garde.titre = constat.niveau, constat.titre
                garde.explication, garde.correction = constat.explication, constat.correction
                garde.hors_note = constat.hors_note
    return retenus


def note(constats):
    """Note sur 100 : on part de 100 et chaque problème retire des points."""
    return max(0, 100 - sum(POIDS[c.niveau] for c in constats if not c.hors_note))
