"""Banc d'essai : mesurer quels outils apportent quoi, et trouver le meilleur mélange.

Le problème : comparer 24 outils demanderait 24 traducteurs sur mesure. Trop long.

L'astuce : pour *mesurer*, on n'a pas besoin de comprendre finement la sortie de
chaque outil — seulement d'en extraire les trouvailles (domaines, adresses mail,
adresses IP, failles). Une extraction générique par motif suffit, et elle marche
sur n'importe quel outil sans traducteur dédié.

On obtient alors, pour une même cible :
  - ce que chaque outil trouve
  - ce qu'il est seul à trouver (son apport réel)
  - le plus petit ensemble d'outils qui trouve tout (le meilleur mélange)

On n'écrit ensuite de vrai traducteur que pour les gagnants.
"""
import re

MOTIFS = {
    "domaines": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I),
    "mails": re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b"),
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "failles": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "urls": re.compile(r"https?://[^\s\"'<>)\]]+", re.I),
}

# Mots qui ressemblent à des domaines mais n'en sont pas : sorties d'outils, versions, fichiers.
BRUIT = re.compile(r"\.(?:py|js|json|txt|go|md|yaml|yml|html|css|log|exe|sh)$", re.I)


def extraire(texte, facette, exclure=()):
    """Les trouvailles d'une sortie d'outil, pour une facette donnée. Ensemble, minuscules.

    `exclure` sert à retirer la cible elle-même : un outil qui échoue affiche souvent
    le domaine visé dans son message d'erreur, et le compter serait une fausse trouvaille.
    """
    motif = MOTIFS.get(facette)
    if motif is None:
        raise ValueError(f"facette inconnue : {facette} (connues : {', '.join(MOTIFS)})")
    ecartes = {str(valeur).strip().lower() for valeur in exclure if str(valeur).strip()}
    trouvailles = set()
    for brut in motif.findall(texte or ""):
        valeur = brut.strip().lower().rstrip(".,;:")
        if facette == "domaines" and BRUIT.search(valeur):
            continue
        if valeur and valeur not in ecartes:
            trouvailles.add(valeur)
    return trouvailles


def mesurer(sorties, facette, exclure=()):
    """sorties : {nom_outil: texte brut}. Renvoie ce que chacun trouve et son apport propre."""
    par_outil = {nom: extraire(texte, facette, exclure) for nom, texte in sorties.items()}
    union = set().union(*par_outil.values()) if par_outil else set()
    uniques = {}
    for nom, trouvailles in par_outil.items():
        autres = set().union(*[t for a, t in par_outil.items() if a != nom]) if len(par_outil) > 1 else set()
        uniques[nom] = trouvailles - autres
    return {"facette": facette, "par_outil": par_outil, "union": union, "uniques": uniques}


def meilleur_melange(mesure):
    """Le plus petit ensemble d'outils qui trouve tout ce que l'union trouve.

    Choix glouton : à chaque tour on prend l'outil qui ajoute le plus de nouvelles
    trouvailles. En cas d'égalité, le nom le plus court (souvent l'outil le plus simple).
    """
    reste = set(mesure["union"])
    disponibles = dict(mesure["par_outil"])
    melange = []
    while reste and disponibles:
        meilleur = max(disponibles,
                       key=lambda nom: (len(disponibles[nom] & reste), -len(nom)))
        apport = disponibles[meilleur] & reste
        if not apport:
            break
        melange.append({"outil": meilleur, "apport": len(apport)})
        reste -= apport
        del disponibles[meilleur]
    inutiles = [nom for nom in mesure["par_outil"] if nom not in {m["outil"] for m in melange}]
    return {"melange": melange, "inutiles": sorted(inutiles), "non_couvert": sorted(reste)}


def en_texte(mesure, melange):
    total = len(mesure["union"])
    lignes = [f"BANC D'ESSAI — facette « {mesure['facette']} »",
              f"{len(mesure['par_outil'])} outils comparés, {total} trouvailles au total", ""]
    lignes.append("CE QUE CHAQUE OUTIL APPORTE")
    classement = sorted(mesure["par_outil"].items(), key=lambda c: -len(c[1]))
    for nom, trouvailles in classement:
        seul = len(mesure["uniques"][nom])
        part = f"{100 * len(trouvailles) // total}%" if total else "—"
        lignes.append(f"  {nom:18} {len(trouvailles):5} trouvés ({part:>4})   "
                      f"{seul:4} que lui seul trouve")
    lignes += ["", "LE MEILLEUR MÉLANGE (le plus petit qui trouve tout)"]
    for rang, etape in enumerate(melange["melange"], 1):
        lignes.append(f"  {rang}. {etape['outil']:18} +{etape['apport']} trouvailles")
    if melange["inutiles"]:
        lignes += ["", "N'APPORTENT RIEN DE PLUS (déjà couverts par le mélange)",
                   "  " + ", ".join(melange["inutiles"])]
    return "\n".join(lignes)
