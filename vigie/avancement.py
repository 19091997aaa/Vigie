"""Où en est un outil lancé depuis « Lancer un outil » : avancement honnête, en direct.

Peu d'outils disent eux-mêmes où ils en sont. Vigie ne montre donc JAMAIS un faux
pourcentage :

1. **Vrai pourcentage** quand l'outil l'écrit lui-même dans ses dernières lignes
   (« 45% », « Requests: 120/400 », barre de progression type tqdm).
2. Sinon, **estimation** d'après la durée des lancements réussis précédents du même
   outil sur cet ordinateur (« d'habitude 3 min »). Plafonnée à 95 % : on ne dit
   « fini » que quand l'outil a vraiment fini.
3. Sinon (premier lancement), **pas de pourcentage** : le temps écoulé, le temps
   maximum avant l'arrêt automatique, et ce que l'outil a déjà écrit.

Les dernières lignes écrites par l'outil restent visibles, repliées (en anglais).
"""
import codecs
import json
import os
import re
import threading
import time

from . import outils

FICHIER_DUREES = "durees-outils.json"     # dans le dossier journal/
GARDEES = 5                               # durées gardées par outil
PLAFOND_ESTIMATION = 95

# Un pourcentage écrit par l'outil : « 45% », « 45.5 % », « (27%) ».
_POURCENT = re.compile(r"(?<![\d.])(\d{1,3}(?:[.,]\d+)?)\s?%")
# « Requests: 120/400 » (Nuclei avec -stats), « Progress: 120 / 400 » (gobuster, ffuf…).
_FRACTION = re.compile(r"(?:requests|progress|progression|done|scanned|tested)\s*:?\s*"
                       r"\[?\s*(\d+)\s*/\s*(\d+)", re.I)


def _duree(secondes):
    from . import spiderfoot
    return spiderfoot.duree(secondes) or "0 s"


class Suivi:
    """Reçoit la sortie de l'outil au fil de l'eau (depuis lancer_seul._executer)."""

    def __init__(self, delai=None, habituel=None):
        self.depart = time.monotonic()
        self.delai = delai
        self.habituel = habituel
        self._verrou = threading.Lock()
        self._decodeurs = {}
        self._queue = {"sortie": "", "erreurs": ""}   # fin de chaque flux (8 Ko)
        self._lignes = 0                              # lignes de résultat (sortie)
        self._ecrit = False

    def ajouter(self, flux, octets):
        decodeur = self._decodeurs.setdefault(
            flux, codecs.getincrementaldecoder("utf-8")(errors="replace"))
        texte = decodeur.decode(octets)
        with self._verrou:
            self._ecrit = True
            if flux == "sortie":
                self._lignes += texte.count("\n")
            self._queue[flux] = (self._queue.get(flux, "") + texte)[-8192:]

    def dernieres_lignes(self, nombre=6):
        """Les dernières lignes (sortie et erreurs), sans couleurs ni barres effacées."""
        with self._verrou:
            texte = self._queue["sortie"] + "\n" + self._queue["erreurs"]
        morceaux = [m.strip() for m in re.split(r"[\r\n]+", outils.sans_couleurs(texte))]
        return [m[:200] for m in morceaux if m][-nombre:]

    def vrai_pourcent(self):
        """Le pourcentage écrit par l'outil dans ses 3 dernières lignes, ou None."""
        for ligne in reversed(self.dernieres_lignes(3)):
            fraction = _FRACTION.search(ligne)
            if fraction and int(fraction.group(2)) > 0:
                return min(100.0, 100.0 * int(fraction.group(1)) / int(fraction.group(2)))
            trouves = _POURCENT.findall(ligne)
            if trouves:
                valeur = float(trouves[-1].replace(",", "."))
                if 0 <= valeur <= 100:
                    return valeur
        return None

    def etat(self):
        """Ce que la page affiche : un dict simple (envoyé tel quel en JSON)."""
        ecoule = time.monotonic() - self.depart
        with self._verrou:
            lignes, ecrit = self._lignes, self._ecrit
        vrai = self.vrai_pourcent()
        if vrai is not None:
            pourcent, sorte = round(vrai), "outil"
            phrase = f"L'outil dit lui-même qu'il en est à {round(vrai)} %."
        elif self.habituel:
            pourcent = min(PLAFOND_ESTIMATION, round(100 * ecoule / self.habituel))
            sorte = "estimation"
            if ecoule < self.habituel:
                phrase = (f"Estimation : d'habitude, cet outil met environ "
                          f"{_duree(self.habituel)} ici. Il reste à peu près "
                          f"{_duree(self.habituel - ecoule)}.")
            else:
                phrase = (f"Plus long que d'habitude (environ {_duree(self.habituel)}). "
                          "Il travaille encore : la cible est peut-être plus grosse.")
        else:
            pourcent, sorte = None, "aucun"
            phrase = ("Cet outil ne dit pas où il en est, et c'est son premier lancement "
                      "ici : Vigie ne peut pas encore estimer la durée. La prochaine "
                      "fois, il pourra.")
        if lignes:
            activite = (f"Il a déjà écrit {lignes} ligne{'s' if lignes > 1 else ''} "
                        "de résultat.")
        elif ecrit:
            activite = "Il travaille (il écrit des messages, pas encore de résultat)."
        elif ecoule < 5:
            activite = "Il démarre…"
        else:
            activite = ("Il n'a encore rien écrit : beaucoup d'outils gardent tout et "
                        "écrivent seulement à la fin.")
        part_delai = None
        if self.delai:
            part_delai = min(100, round(100 * ecoule / self.delai))
        return {"pourcent": pourcent, "sorte": sorte, "phrase": phrase,
                "activite": activite, "ecoule": _duree(ecoule),
                "maximum": _duree(self.delai) if self.delai else "",
                "part_delai": part_delai, "lignes": lignes,
                "dernieres": self.dernieres_lignes()}


# --- Durées habituelles (apprises sur cet ordinateur) -------------------------------

def _chemin(journal):
    return os.path.join(journal, FICHIER_DUREES)


def _lire(journal):
    try:
        with open(_chemin(journal), encoding="utf-8") as lu:
            donnees = json.load(lu)
        return donnees if isinstance(donnees, dict) else {}
    except (OSError, ValueError):
        return {}


def habituel(journal, outil):
    """La durée habituelle (médiane des derniers lancements réussis) en secondes, ou None."""
    durees = sorted(d for d in _lire(journal).get((outil or "").lower(), [])
                    if isinstance(d, (int, float)) and d > 0)
    if not durees:
        return None
    milieu = len(durees) // 2
    return durees[milieu] if len(durees) % 2 else (durees[milieu - 1] + durees[milieu]) / 2


def noter(journal, outil, secondes):
    """Retient la durée d'un lancement réussi et complet (jamais un arrêt au maximum)."""
    try:
        secondes = float(secondes)
    except (TypeError, ValueError):
        return
    if secondes <= 0 or not outil:
        return
    donnees = _lire(journal)
    cle = outil.lower()
    donnees[cle] = (list(donnees.get(cle, [])) + [round(secondes, 1)])[-GARDEES:]
    try:
        os.makedirs(journal, exist_ok=True)
        provisoire = _chemin(journal) + ".tmp"
        with open(provisoire, "w", encoding="utf-8") as ecrit:
            json.dump(donnees, ecrit, ensure_ascii=False, indent=1)
        os.replace(provisoire, _chemin(journal))
    except OSError:
        pass
