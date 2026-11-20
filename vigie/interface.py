"""Vigie dans le navigateur : la même mécanique que la commande, avec un formulaire.

Le moteur tourne sur l'ordinateur. L'écran s'ouvre dans un navigateur, sur
l'ordinateur lui-même ou sur un téléphone du même Wi-Fi (option --reseau-local,
protégée par un code).

Seuls les contrôles sans action sur les machines sont proposés ici.
"""
import html
import os
import re
import secrets
import socket
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, rapport
from .cli import dossier_rapport, lancer, nettoyer_domaine
from .modeles import Cible
from .modules import MODULES, PAR_DEFAUT

NOM_RAPPORT = re.compile(r"[a-z0-9_-]{3,120}")

CSS_FORM = """
.corps { padding:30px 40px 10px; }
form { display:grid; gap:18px; margin:4px 0 8px; }
label { display:grid; gap:7px; font-weight:700; font-size:14px; color:var(--encre); }
input { font:inherit; padding:13px 15px; border:1.5px solid #cfd6e1; border-radius:10px; }
input:focus { outline:none; border-color:var(--navy); }
button { font:inherit; font-size:16px; font-weight:800; padding:15px 18px; border:0;
  border-radius:10px; background:var(--navy); color:#fff; cursor:pointer; }
button:hover { background:#1c3a68; }
.aide { font-size:13.5px; color:var(--gris); font-weight:400; }
.erreur { padding:13px 16px; border-radius:10px; border-left:4px solid #b3261e;
  background:#fbeceb; color:#8a1d16; margin-bottom:6px; }
.rapports { list-style:none; padding:0; margin:0; }
.rapports a { display:flex; align-items:center; gap:10px; padding:13px 16px; margin:8px 0;
  border:1px solid var(--trait); border-radius:10px; text-decoration:none; color:var(--navy);
  font-weight:600; }
.rapports a:hover { border-color:var(--navy); background:var(--fond); }
.rapports a::before { content:"\\1F4C4"; }
"""

PAGE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie</title>
<style>{css}{cssform}</style></head><body><main>
<div class="couv">
<div class="enseigne">{logo}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Nouveau diagnostic</h1>
<div class="meta"><span>Audit d'exposition pour petites entreprises</span></div>
</div>
<div class="corps">
{message}
<form method="post" action="/diagnostic">
<label>Nom de domaine de la société
<input name="domaine" placeholder="exemple.fr" required autocapitalize="none" autocomplete="off">
</label>
<label>Nom de la société <span class="aide">Affiché en tête du rapport.</span>
<input name="societe" autocomplete="off"></label>
<button type="submit">Lancer le diagnostic</button>
<p class="aide">Contrôles lancés&nbsp;: {controles}. Ils lisent des informations publiques et
prennent environ une minute.</p>
</form>
<h2>Rapports déjà produits</h2>
{rapports}
</div>
<footer>Vigie {version}. Diagnostic réservé à la société du client, avec son accord.</footer>
</main></body></html>"""


def _liste_rapports(sortie):
    if not os.path.isdir(sortie):
        return "<p class='aide'>Aucun rapport pour l'instant.</p>"
    noms = sorted((nom for nom in os.listdir(sortie)
                   if NOM_RAPPORT.fullmatch(nom)
                   and os.path.isfile(os.path.join(sortie, nom, "rapport.html"))), reverse=True)
    if not noms:
        return "<p class='aide'>Aucun rapport pour l'instant.</p>"
    return "<ul class='rapports'>" + "".join(
        f"<li><a href='/rapport/{nom}'>{html.escape(nom)}</a></li>" for nom in noms) + "</ul>"


def page_accueil(sortie, erreur=""):
    message = f"<p class='erreur'>{html.escape(erreur)}</p>" if erreur else ""
    controles = ", ".join(MODULES[nom]["nom"].lower() for nom in PAR_DEFAUT)
    return PAGE.format(css=rapport.CSS, cssform=CSS_FORM, logo=rapport.LOGO, message=message,
                       controles=html.escape(controles),
                       rapports=_liste_rapports(sortie), version=__version__)


def traiter_formulaire(corps, sortie):
    """Lance le diagnostic demandé. Renvoie le nom du dossier du rapport."""
    champs = urllib.parse.parse_qs(corps)
    domaine = nettoyer_domaine(champs.get("domaine", [""])[0])
    societe = champs.get("societe", [""])[0].strip()[:120]
    resultat = lancer(Cible(domaine, societe), PAR_DEFAUT)
    dossier = dossier_rapport(sortie, resultat)
    rapport.ecrire(resultat, dossier)
    return os.path.basename(dossier)


def fabrique(sortie, code):
    class Requete(BaseHTTPRequestHandler):
        server_version = "Vigie"

        def log_message(self, *arguments):  # pas de journal bavard dans le terminal
            pass

        def _envoyer(self, statut, contenu, entetes=()):
            donnees = contenu.encode("utf-8")
            self.send_response(statut)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(donnees)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for nom, valeur in entetes:
                self.send_header(nom, valeur)
            self.end_headers()
            self.wfile.write(donnees)

        def _autorise(self):
            """En mode réseau local, il faut le code affiché dans le terminal."""
            if not code:
                return True
            return f"vigie={code}" in self.headers.get("Cookie", "")

        def do_GET(self):
            adresse = urllib.parse.urlsplit(self.path)
            if code and urllib.parse.parse_qs(adresse.query).get("code", [""])[0] == code:
                self._envoyer(303, "", [("Location", "/"), (
                    "Set-Cookie", f"vigie={code}; HttpOnly; SameSite=Strict; Path=/")])
                return
            if not self._autorise():
                self._envoyer(403, "<p>Accès refusé. Ouvrez l'adresse affichée dans le terminal.</p>")
                return
            if adresse.path == "/":
                self._envoyer(200, page_accueil(sortie))
                return
            trouve = re.fullmatch(r"/rapport/([a-z0-9_-]{3,120})", adresse.path)
            if trouve:
                chemin = os.path.join(sortie, trouve.group(1), "rapport.html")
                if os.path.isfile(chemin):
                    with open(chemin, encoding="utf-8") as fichier:
                        self._envoyer(200, fichier.read())
                    return
            self._envoyer(404, "<p>Page introuvable.</p>")

        def do_POST(self):
            if not self._autorise():
                self._envoyer(403, "<p>Accès refusé.</p>")
                return
            if self.path != "/diagnostic":
                self._envoyer(404, "<p>Page introuvable.</p>")
                return
            taille = min(int(self.headers.get("Content-Length", "0") or 0), 4096)
            corps = self.rfile.read(taille).decode("utf-8", "replace")
            try:
                nom = traiter_formulaire(corps, sortie)
            except ValueError as erreur:
                self._envoyer(400, page_accueil(sortie, str(erreur)))
                return
            self._envoyer(303, "", [("Location", f"/rapport/{nom}")])

    return Requete


def _adresse_locale():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sonde:
            sonde.connect(("192.0.2.1", 9))  # aucune donnée envoyée : sert à lire l'adresse locale
            return sonde.getsockname()[0]
    except OSError:
        return "adresse-de-cet-ordinateur"


def servir(port=8765, reseau_local=False, sortie="rapports"):
    code = secrets.token_urlsafe(9) if reseau_local else ""
    hote = "0.0.0.0" if reseau_local else "127.0.0.1"
    serveur = ThreadingHTTPServer((hote, port), fabrique(sortie, code))
    print(f"Vigie {__version__} est ouvert.")
    print(f"  Sur cet ordinateur : http://localhost:{port}/" + (f"?code={code}" if code else ""))
    if reseau_local:
        print(f"  Sur le téléphone (même Wi-Fi) : http://{_adresse_locale()}:{port}/?code={code}")
        print("  Le code dans l'adresse protège l'accès. Ne partagez pas cette adresse.")
    print("Pour arrêter : Ctrl + C")
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        print("\nVigie est arrêté.")
    finally:
        serveur.server_close()
