"""Export PDF du rapport, sans dépendance à installer.

On ne réinvente pas la mise en page : on imprime le rapport HTML (déjà soigné,
avec son CSS @media print) via un navigateur Chromium déjà présent sur la machine
— Edge sur Windows, Chrome sur Mac, Chromium sur Linux. Si aucun n'est trouvé,
on le dit clairement et on renvoie vers « Ctrl+P → Enregistrer en PDF ».
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


class PasDeNavigateur(Exception):
    """Aucun navigateur Chromium trouvé pour fabriquer le PDF."""


# Emplacements habituels, par système. On teste ceux-ci avant de chercher dans le PATH.
CHEMINS = {
    "win32": [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ],
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ],
    "linux": [
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/microsoft-edge",
    ],
}
NOMS_PATH = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
             "microsoft-edge", "microsoft-edge-stable", "msedge", "chrome"]


def trouver_navigateur():
    """Renvoie le chemin d'un navigateur Chromium, ou None si aucun n'est trouvé."""
    for chemin in CHEMINS.get(sys.platform, []):
        if os.path.exists(chemin):
            return chemin
    for nom in NOMS_PATH:
        trouve = shutil.which(nom)
        if trouve:
            return trouve
    return None


def html_vers_pdf(chemin_html, chemin_pdf, navigateur=None):
    """Convertit un fichier HTML en PDF via un navigateur sans fenêtre. Renvoie le chemin du PDF."""
    nav = navigateur or trouver_navigateur()
    if not nav:
        raise PasDeNavigateur(
            "Aucun navigateur Chrome, Edge ou Chromium n'a été trouvé pour l'export PDF. "
            "Ouvre le rapport HTML dans ton navigateur et fais Ctrl+P puis "
            "« Enregistrer au format PDF ».")
    url = pathlib.Path(chemin_html).resolve().as_uri()
    with tempfile.TemporaryDirectory() as profil:
        subprocess.run(
            [nav, "--headless=new", "--disable-gpu", "--no-sandbox",
             f"--user-data-dir={profil}", "--no-pdf-header-footer",
             f"--print-to-pdf={chemin_pdf}", url],
            check=True, capture_output=True, timeout=90)
    if not os.path.exists(chemin_pdf):  # certains Chrome anciens ignorent --headless=new
        with tempfile.TemporaryDirectory() as profil:
            subprocess.run(
                [nav, "--headless", "--disable-gpu", "--no-sandbox",
                 f"--user-data-dir={profil}", "--no-pdf-header-footer",
                 f"--print-to-pdf={chemin_pdf}", url],
                check=True, capture_output=True, timeout=90)
    return chemin_pdf


def ecrire_pdf(chemins_html, navigateur=None):
    """Convertit en PDF chaque fichier HTML donné (dict nom->chemin). Renvoie dict nom->chemin PDF."""
    nav = navigateur or trouver_navigateur()
    if not nav:
        raise PasDeNavigateur(
            "Aucun navigateur Chrome, Edge ou Chromium n'a été trouvé pour l'export PDF. "
            "Ouvre le rapport HTML et fais Ctrl+P puis « Enregistrer au format PDF ».")
    produits = {}
    for nom, chemin_html in chemins_html.items():
        if not chemin_html.endswith(".html"):
            continue
        chemin_pdf = chemin_html[:-5] + ".pdf"
        html_vers_pdf(chemin_html, chemin_pdf, nav)
        produits[os.path.basename(chemin_pdf)] = chemin_pdf
    return produits
