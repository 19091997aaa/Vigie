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
    """Lance une commande d'installation. Renvoie (réussi, message court, sortie)."""
    programme = shutil.which(commande[0])
    if not programme:
        return False, f"{commande[0]} absent", ""
    try:
        fini = subprocess.run([programme] + commande[1:], capture_output=True,
                              text=True, timeout=delai, errors="replace")
    except subprocess.TimeoutExpired:
        return False, f"dépassement de {delai} s", ""
    sortie = (fini.stdout or "") + "\n" + (fini.stderr or "")
    if fini.returncode == 0:
        return True, "", sortie
    erreur = (fini.stderr or fini.stdout or "").strip().splitlines()
    return False, (erreur[-1][:140] if erreur else f"code {fini.returncode}"), sortie


# pipx annonce les binaires posés sous « These apps are now globally available ».
APPS_PIPX = re.compile(r"^\s*-\s+(\S+)\s*$", re.M)


def binaires_poses(libelle, sortie, proprietaire, nom):
    """Quels exécutables l'installation a réellement posés. L'outil le dit lui-même."""
    if libelle.startswith("pipx"):
        apps = APPS_PIPX.findall(sortie or "")
        if apps:
            return apps
    if libelle == "go":
        return [nom]                     # go install pose le dernier segment du module
    return [nom.lower(), nom]


def repond(binaire, delai=25):
    """L'exécutable démarre-t-il vraiment ? Un paquet installé peut rester une coquille vide."""
    chemin = shutil.which(binaire)
    if not chemin:
        return False
    for arguments in (["--help"], ["-h"], []):
        try:
            fini = subprocess.run([chemin] + arguments, capture_output=True,
                                  text=True, timeout=delai, errors="replace")
        except (subprocess.TimeoutExpired, OSError):
            continue
        # Beaucoup d'outils renvoient un code non nul sur --help : ce qui compte,
        # c'est qu'ils aient écrit quelque chose au lieu de planter au démarrage.
        if len(((fini.stdout or "") + (fini.stderr or "")).strip()) > 40:
            return True
    return False


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
    """Essaie les méthodes l'une après l'autre, puis vérifie que l'outil démarre vraiment."""
    essais = methodes(outil)
    if not essais:
        return {"nom": outil["nom"], "installe": False, "repond": False, "binaire": "",
                "methode": "", "raison": "pas de dépôt"}
    if a_blanc:
        return {"nom": outil["nom"], "installe": False, "repond": False, "binaire": "",
                "methode": essais[0][0], "raison": "à blanc : " + " ".join(essais[0][1])}
    proprietaire, depot_nom = depot(outil.get("lien", ""))
    raisons = []
    for libelle, commande in essais:
        reussi, message, sortie = _lancer(commande)
        if not reussi:
            raisons.append(f"{libelle} : {message}")
            continue
        # Installé n'est pas prêt : on lance l'exécutable pour le vérifier.
        for binaire in binaires_poses(libelle, sortie, proprietaire, depot_nom):
            if repond(binaire):
                return {"nom": outil["nom"], "installe": True, "repond": True,
                        "binaire": binaire, "methode": libelle, "raison": ""}
        return {"nom": outil["nom"], "installe": True, "repond": False, "binaire": "",
                "methode": libelle, "raison": "installé mais ne démarre pas"}
    return {"nom": outil["nom"], "installe": False, "repond": False, "binaire": "",
            "methode": "", "raison": " | ".join(raisons)[:300]}


def installer(outils, a_blanc=False, journal=print, parallele=1):
    """Installe une liste d'outils et renvoie le compte rendu de chacun.

    Installer, c'est surtout attendre un téléchargement : à la file, la machine
    ne fait rien la plupart du temps. En lançant plusieurs installations de front,
    on divise l'attente d'autant. Le premier outil passe seul, pour laisser pipx
    préparer son environnement partagé sans que huit processus se marchent dessus.
    """
    if parallele <= 1 or len(outils) < 2 or a_blanc:
        comptes_rendus = []
        for numero, outil in enumerate(outils, 1):
            journal(f"[{numero}/{len(outils)}] {outil['nom']}…")
            resultat = installer_un(outil, a_blanc)
            etat = "ok" if resultat["installe"] else "échec"
            journal(f"    {etat} {resultat['methode']} {resultat['raison']}".rstrip())
            comptes_rendus.append(resultat)
        return comptes_rendus

    import concurrent.futures
    total = len(outils)
    journal(f"[1/{total}] {outils[0]['nom']}… (seul, le temps que pipx se prépare)")
    premier = installer_un(outils[0], a_blanc)
    journal(f"    {'ok' if premier['installe'] else 'échec'} {premier['methode']}".rstrip())
    comptes_rendus = [premier]
    faits = 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallele) as equipe:
        en_cours = {equipe.submit(installer_un, outil, a_blanc): outil
                    for outil in outils[1:]}
        journal(f"  ({len(en_cours)} outils restants, {parallele} à la fois)")
        for fini in concurrent.futures.as_completed(en_cours):
            resultat = fini.result()
            faits += 1
            etat = "ok   " if resultat["installe"] else "échec"
            journal(f"[{faits}/{total}] {etat} {resultat['nom']} "
                    f"{resultat['methode']} {resultat['raison']}".rstrip())
            comptes_rendus.append(resultat)
    return comptes_rendus


def resume(comptes_rendus):
    """Trois états, pas deux : installé ne veut pas dire utilisable."""
    reussis = [c for c in comptes_rendus if c["installe"]]
    prets = [c for c in reussis if c.get("repond")]
    return {"total": len(comptes_rendus), "installes": len(reussis),
            "prets": len(prets),
            "coquilles": len(reussis) - len(prets),
            "echecs": len(comptes_rendus) - len(reussis),
            "par_methode": {m: sum(1 for c in reussis if c["methode"] == m)
                            for m in sorted({c["methode"] for c in reussis})}}
