"""Installation en masse des outils du catalogue, par catégorie.

Le catalogue des 222 outils ne donne qu'un lien GitHub : on ne connaît pas
d'avance la bonne commande d'installation. Plutôt que de la deviner, on essaie
plusieurs méthodes dans l'ordre et on note celle qui marche. L'essai est la mesure.

    python3 -m vigie installer --categorie "OSINT : pseudos, e-mails, images, métadonnées"
    python3 -m vigie installer --tous --a-blanc

Rien n'est installé en dehors des gestionnaires standards (pipx, go, npm), qui
isolent chaque outil. Aucun script distant n'est exécuté.
"""
import json
import os
import re
import shutil
import subprocess

CATALOGUE = os.path.join(os.path.dirname(__file__), "catalogue_outils.json")
DEPOT = re.compile(r"github\.com/([^/]+)/([^/#?]+)")


def charger(chemin=CATALOGUE):
    with open(chemin, encoding="utf-8") as fichier:
        return json.load(fichier)


def categories(outils):
    """Les catégories et le nombre d'outils dans chacune."""
    compte = {}
    for outil in outils:
        compte[outil["categorie"]] = compte.get(outil["categorie"], 0) + 1
    return compte


def depot(lien):
    """https://github.com/owner/repo -> ('owner', 'repo'), sinon None."""
    trouve = DEPOT.search(lien or "")
    return (trouve.group(1), trouve.group(2).removesuffix(".git")) if trouve else None


def _lancer(commande, delai=600):
    """Lance une commande d'installation. Renvoie (réussi, message court)."""
    programme = shutil.which(commande[0])
    if not programme:
        return False, f"{commande[0]} absent"
    try:
        fini = subprocess.run([programme] + commande[1:], capture_output=True,
                              text=True, timeout=delai)
    except subprocess.TimeoutExpired:
        return False, f"dépassement de {delai} s"
    if fini.returncode == 0:
        return True, ""
    erreur = (fini.stderr or fini.stdout or "").strip().splitlines()
    return False, (erreur[-1][:140] if erreur else f"code {fini.returncode}")


def methodes(outil):
    """Les commandes à essayer pour cet outil, dans l'ordre du plus propre au plus large."""
    couple = depot(outil.get("lien", ""))
    if not couple:
        return []
    proprietaire, nom = couple
    simple = nom.lower()
    return [
        ("pipx (PyPI)", ["pipx", "install", simple]),
        ("pipx (dépôt)", ["pipx", "install", f"git+https://github.com/{proprietaire}/{nom}"]),
        ("go", ["go", "install", f"github.com/{proprietaire}/{nom}@latest"]),
        ("npm", ["npm", "install", "-g", simple]),
    ]


def installer_un(outil, a_blanc=False):
    """Essaie les méthodes l'une après l'autre. Renvoie un compte rendu."""
    essais = methodes(outil)
    if not essais:
        return {"nom": outil["nom"], "installe": False, "methode": "", "raison": "pas de dépôt"}
    if a_blanc:
        return {"nom": outil["nom"], "installe": False, "methode": essais[0][0],
                "raison": "à blanc : " + " ".join(essais[0][1])}
    raisons = []
    for libelle, commande in essais:
        reussi, message = _lancer(commande)
        if reussi:
            return {"nom": outil["nom"], "installe": True, "methode": libelle, "raison": ""}
        raisons.append(f"{libelle} : {message}")
    return {"nom": outil["nom"], "installe": False, "methode": "",
            "raison": " | ".join(raisons)[:300]}


def installer(outils, a_blanc=False, journal=print):
    """Installe une liste d'outils et renvoie le compte rendu de chacun."""
    comptes_rendus = []
    for numero, outil in enumerate(outils, 1):
        journal(f"[{numero}/{len(outils)}] {outil['nom']}…")
        resultat = installer_un(outil, a_blanc)
        etat = "ok" if resultat["installe"] else "échec"
        journal(f"    {etat} {resultat['methode']} {resultat['raison']}".rstrip())
        comptes_rendus.append(resultat)
    return comptes_rendus


def resume(comptes_rendus):
    reussis = [c for c in comptes_rendus if c["installe"]]
    return {"total": len(comptes_rendus), "installes": len(reussis),
            "echecs": len(comptes_rendus) - len(reussis),
            "par_methode": {m: sum(1 for c in reussis if c["methode"] == m)
                            for m in sorted({c["methode"] for c in reussis})}}
