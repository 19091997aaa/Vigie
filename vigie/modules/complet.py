"""Le diagnostic complet : les outils de la famille « diag gratuit » ajoutés le 24/11/2026.

But d'Anass : que les 42 outils du diagnostic gratuit tournent ensemble, quitte à ce
que le contrôle soit plus long. Ce fichier branche ceux qui n'étaient pas encore dans
l'enchaînement. Chacun reçoit l'entrée qu'il attend, tirée du domaine (voir
vigie/indices.py) :

  Amass        -> le domaine (mode passif : sources publiques seulement)
  dnsx         -> les adresses annexes trouvées par Subfinder et Amass
  WhatWeb      -> l'adresse du site (mode discret : UNE visite, comme un visiteur)
  sitespeed.io -> l'adresse du site (une visite de la page d'accueil)
  EyeWitness   -> l'adresse du site (une capture d'écran)
  uncover      -> le domaine (questionne Shodan/Censys : rien n'est envoyé à la société)
  Metagoofil   -> le domaine (cherche ses documents publics dans les moteurs)
  Exiv2        -> les photos publiées sur la page d'accueil
  Instaloader  -> le compte Instagram affiché sur le site de la société
  PhoneInfoga  -> les numéros affichés sur le site (gardés en mémoire, jamais écrits)
  Sherlock, Maigret, user-scanner, Social Analyzer -> le nom de la société (marque)
  ArchiveBox   -> l'adresse du site (copie datée de la page d'accueil)
  GHunt        -> l'adresse Gmail du dirigeant, SEULEMENT avec son accord écrit

Règles qui ne bougent pas : rien de tout ça ne cherche de faille, ne teste de port, ni
n'interroge de base de fuites. Les noms de personnes et les numéros ne sont que COMPTÉS.
"""
import base64
import glob
import json
import os
import re
import tempfile
import urllib.parse

from .. import indices, outils, reseau
from ..modeles import IMPORTANT, INFO, OK, Constat, ControleImpossible
from . import metadonnees, pseudos, sousdomaines, telephone

BLOC = "Exposition"
TRAVAIL = os.path.expanduser("~/vigie-travail")


def _url(cible):
    return "https://" + cible.domaine


def _derniere_ligne(texte):
    lignes = [l.strip() for l in (texte or "").splitlines() if l.strip()]
    return lignes[-1][:200] if lignes else ""


# ---------------------------------------------------------------------------
# Amass (mode passif) : 2e avis sur les adresses annexes.

def lire_amass(texte, domaine):
    """Les noms du domaine cités dans la sortie d'Amass (quel que soit son format)."""
    motif = re.compile(r"(?<![a-z0-9_.-])((?:[a-z0-9_-]+\.)+" + re.escape(domaine) + r")(?![a-z0-9-])")
    return sorted({nom.rstrip(".") for nom in motif.findall((texte or "").lower())})


def analyser_amass(cible):
    resultat = outils.executer_detail(
        "amass", ["enum", "-passive", "-d", cible.domaine, "-timeout", "5", "-nocolor"],
        delai=420)
    noms = lire_amass(resultat.stdout + "\n" + resultat.stderr, cible.domaine)
    if not noms and "flag provided but not defined" in resultat.stderr:
        raise ControleImpossible("cette version d'Amass ne connaît plus le mode passif : "
                                 "Vigie ne la lance pas en mode actif")
    deja = set((cible.indices.get("sousdomaines") or {}).get("sous_domaines", []))
    nouveaux = [n for n in noms if n not in deja]
    brut = {"sous_domaines": noms, "en_plus_de_subfinder": nouveaux}
    if nouveaux:
        return [Constat(
            BLOC, INFO, f"Amass voit {len(nouveaux)} adresses annexes de plus",
            "En plus de celles déjà listées : " + ", ".join(nouveaux[:15])
            + (" et d'autres" if len(nouveaux) > 15 else "") + ". Chaque adresse oubliée "
            "est une porte d'entrée possible.",
            "Vérifier que chacune sert encore ; supprimer les autres.",
            cle="sous_domaines_amass", hors_note=True)], brut
    return [Constat(BLOC, OK, "Amass confirme la liste des adresses annexes",
                    "Il ne trouve aucune adresse de plus que Subfinder.",
                    cle="sous_domaines")], brut


# ---------------------------------------------------------------------------
# dnsx : les adresses annexes répondent-elles encore ? Un alias vers un service disparu
# peut être repris par un inconnu (« prise de contrôle de sous-domaine »).

def lire_dnsx(texte):
    """{nom: {"a": [...], "cname": [...]}} d'après la sortie JSON de dnsx (une ligne par nom)."""
    fiches = {}
    for ligne in (texte or "").splitlines():
        try:
            fiche = json.loads(ligne)
        except json.JSONDecodeError:
            continue
        if isinstance(fiche, dict) and fiche.get("host"):
            fiches[fiche["host"].lower().rstrip(".")] = {
                "a": fiche.get("a") or [], "cname": fiche.get("cname") or []}
    return fiches


def noms_a_verifier(cible):
    noms = [cible.domaine, "www." + cible.domaine]
    for module in ("sousdomaines", "sousdomaines_amass"):
        noms += (cible.indices.get(module) or {}).get("sous_domaines", [])
    return list(dict.fromkeys(noms))  # sans doublon, dans l'ordre


def analyser_dnsx(cible):
    noms = noms_a_verifier(cible)
    texte = outils.executer("dnsx", ["-silent", "-json", "-a", "-cname", "-resp",
                                     "-r", ",".join(reseau.SERVEURS_DNS)],
                            delai=180, entree="\n".join(noms) + "\n")
    fiches = lire_dnsx(texte)
    orphelins = sorted(n for n, f in fiches.items() if f["cname"] and not f["a"])
    muets = sorted(n for n in noms if n not in fiches and n != "www." + cible.domaine)
    brut = {"verifies": len(noms), "repondent": len(fiches), "alias_orphelins": orphelins,
            "muets": muets}
    constats = []
    if orphelins:
        constats.append(Constat(
            BLOC, IMPORTANT, f"{len(orphelins)} adresses annexes pointent vers un service disparu",
            "Adresses concernées : " + ", ".join(orphelins[:10]) + ". Elles renvoient vers "
            "un service extérieur qui ne répond plus. Un inconnu peut parfois ouvrir ce "
            "service à son nom et publier ce qu'il veut sous votre adresse. À confirmer "
            "à la relecture.",
            "Supprimer ces alias dans la zone DNS s'ils ne servent plus.",
            cle="alias_orphelins"))
    if muets:
        constats.append(Constat(
            BLOC, INFO, f"{len(muets)} adresses annexes ne répondent plus",
            "Elles apparaissent dans les sources publiques mais ne mènent plus nulle part : "
            + ", ".join(muets[:10]) + ". Ce sont souvent des restes d'anciens services.",
            "Faire le ménage dans la zone DNS.", cle="adresses_muettes", hors_note=True))
    if not constats:
        constats.append(Constat(BLOC, OK, "Les adresses annexes répondent normalement",
                                f"{len(fiches)} adresses vérifiées, aucun alias orphelin.",
                                cle="alias_orphelins"))
    return constats, brut


# ---------------------------------------------------------------------------
# WhatWeb (mode discret, niveau 1 = une seule visite) : technologies du site.

IGNORES = {"Country", "IP", "Title", "HTML5", "Script", "UncommonHeaders", "Meta-Author",
           "Email", "Cookies", "HttpOnly", "RedirectLocation", "X-UA-Compatible",
           "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection",
           "Content-Security-Policy", "Meta-Refresh-Redirect", "Open-Graph-Protocol",
           "Frame", "Google-Analytics", "Via-Proxy", "Access-Control-Allow-Methods",
           "PasswordField", "Bootstrap", "Lightbox", "Modernizr"}


def lire_whatweb(data):
    """[« WordPress 6.4 », « nginx »…] d'après le journal JSON de WhatWeb."""
    technos, avec_version = [], 0
    for entree in data or []:
        for nom, detail in (entree.get("plugins") or {}).items():
            if nom in IGNORES:
                continue
            version = ((detail or {}).get("version") or [""])[0]
            texte = (f"{nom} {version}" if version else nom).strip()
            if nom == "HTTPServer":
                texte = ((detail or {}).get("string") or [nom])[0]
            if texte and texte not in technos:
                technos.append(texte)
                avec_version += bool(version)
    return {"technos": technos, "avec_version": avec_version}


def _whatweb_une_fois(url):
    """(infos ou None, résultat brut de l'outil)."""
    with tempfile.TemporaryDirectory() as dossier:
        journal = os.path.join(dossier, "whatweb.json")
        # Pas de « --no-errors » : quand WhatWeb ne voit rien, on veut savoir pourquoi.
        resultat = outils.executer_detail(
            "whatweb", ["--color=never", "-a", "1", "--open-timeout", "20",
                        "--read-timeout", "30", f"--log-json={journal}", url],
            delai=120, dossier=dossier)
        try:
            with open(journal, encoding="utf-8") as lu:
                return lire_whatweb(json.load(lu)), resultat
        except (OSError, json.JSONDecodeError, ValueError):
            return None, resultat


def analyser_whatweb(cible):
    infos, resultat = _whatweb_une_fois(_url(cible))
    if infos is None:  # deuxième essai : un hoquet du réseau ne suffit pas à conclure
        infos, resultat = _whatweb_une_fois(_url(cible))
    if infos is None:
        if reseau.https_repond(cible.domaine) == reseau.OUI:
            raise ControleImpossible(
                "WhatWeb n'a rien écrit alors que le site répond bien (vérifié par Vigie) : "
                "c'est l'outil qui coince — " + outils.pourquoi(resultat))
        raise ControleImpossible("WhatWeb n'a rien écrit — " + outils.pourquoi(resultat))
    if not infos["technos"]:
        return [], {"whatweb": infos}
    texte = ", ".join(infos["technos"][:12])
    version = (f" {infos['avec_version']} d'entre elles affichent leur version exacte, ce "
               "qui aide un attaquant à viser les failles connues." if infos["avec_version"]
               else "")
    return [Constat(BLOC, INFO, "Technologies du site reconnues par WhatWeb",
                    f"Vues de l'extérieur : {texte}.{version}",
                    "Masquer les numéros de version dans les réglages du serveur et du site."
                    if infos["avec_version"] else "",
                    cle="technos_whatweb", hors_note=True)], {"whatweb": infos}


# ---------------------------------------------------------------------------
# sitespeed.io : vitesse de la page d'accueil.

def _valeur(objet, cle):
    """Première valeur trouvée sous cette clé, n'importe où dans un JSON (médiane si besoin)."""
    if isinstance(objet, dict):
        if cle in objet:
            v = objet[cle]
            if isinstance(v, dict):
                v = v.get("median", v.get("mean"))
            if isinstance(v, (int, float)):
                return v
        enfants = objet.values()
    elif isinstance(objet, list):
        enfants = objet
    else:
        return None
    for enfant in enfants:
        trouve = _valeur(enfant, cle)
        if trouve is not None:
            return trouve
    return None


def lire_sitespeed(dossier):
    mesures = {}
    for chemin in glob.glob(os.path.join(dossier, "**", "*.json"), recursive=True):
        if "browsertime" not in os.path.basename(chemin):
            continue
        try:
            with open(chemin, encoding="utf-8") as lu:
                data = json.load(lu)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        for cle in ("fullyLoaded", "firstContentfulPaint", "largestContentfulPaint"):
            if cle not in mesures:
                v = _valeur(data, cle)
                if v is not None:
                    mesures[cle] = v
    return mesures


def analyser_sitespeed(cible):
    with tempfile.TemporaryDirectory() as dossier:
        sortie = os.path.join(dossier, "resultat")
        resultat = outils.executer_detail(
            "sitespeed.io", [_url(cible), "-n", "1", "--headless", "true",
                             "--outputFolder", sortie], delai=420, dossier=dossier)
        mesures = lire_sitespeed(sortie)
    if not mesures:
        raise ControleImpossible("sitespeed.io n'a rien mesuré (" +
                                 (_derniere_ligne(resultat.stderr or resultat.stdout)
                                  or "navigateur absent ?") + ")")
    charge = mesures.get("fullyLoaded") or mesures.get("largestContentfulPaint")
    if not charge:
        return [], {"sitespeed": mesures}
    secondes = round(charge / 1000, 1)
    lente = secondes > 5
    return [Constat(BLOC, INFO,
                    f"Page d'accueil chargée en {secondes} s" + (" : c'est lent" if lente else ""),
                    "Mesure faite par un vrai navigateur (sitespeed.io). Au-delà de 3 à 5 "
                    "secondes, une partie des visiteurs repart avant d'avoir vu la page.",
                    "Alléger les images et les extensions du site." if lente else "",
                    cle="vitesse_sitespeed", hors_note=True)], {"sitespeed": mesures}


# ---------------------------------------------------------------------------
# EyeWitness : capture d'écran (2e avis de gowitness ; sert au rapport si gowitness rate).

def analyser_eyewitness(cible):
    with tempfile.TemporaryDirectory() as dossier:
        sortie = os.path.join(dossier, "eyewitness")
        resultat = outils.executer_detail(
            "eyewitness", ["--single", _url(cible), "--web", "--no-prompt", "-d", sortie,
                           "--timeout", "30"], delai=240, dossier=dossier)
        images = sorted(glob.glob(os.path.join(sortie, "screens", "*.png")))
        if not images:
            raise ControleImpossible("EyeWitness n'a pas pu photographier la page ("
                                     + (_derniere_ligne(resultat.stderr or resultat.stdout)
                                        or "navigateur absent ?") + ")")
        if os.path.getsize(images[0]) > 2_000_000:
            return [], {"capture": "trop lourde pour le rapport"}
        with open(images[0], "rb") as image:
            contenu = base64.b64encode(image.read()).decode("ascii")
    return [], {"apercu": {"type": "image/png", "image_base64": contenu}}


# ---------------------------------------------------------------------------
# uncover : ce que Shodan, Censys… ont déjà indexé. Aucune question à la société.

def lire_uncover(texte):
    vus = []
    for ligne in (texte or "").splitlines():
        ligne = ligne.strip()
        if re.fullmatch(r"[0-9a-fA-F:.]+:\d{1,5}|[A-Za-z0-9.-]+:\d{1,5}", ligne) and ligne not in vus:
            vus.append(ligne)
    return vus


def analyser_uncover(cible):
    resultat = outils.executer_detail("uncover", ["-q", cible.domaine, "-silent", "-l", "100"],
                                      delai=180)
    services = lire_uncover(resultat.stdout)
    source = "moteurs configurés"
    if not services and re.search(r"key|api|credential", resultat.stderr or "", re.I):
        # Sans clé : la base GRATUITE de Shodan (InternetDB), interrogée sur l'adresse IP
        # du site. Rien n'est envoyé à la société : on lit ce que Shodan a déjà noté.
        try:
            ips = [ip for ip in reseau.dns(cible.domaine, "A") if re.fullmatch(r"[\d.]+", ip)]
        except ControleImpossible:
            ips = []
        if not ips:
            raise ControleImpossible(
                "il faut une clé d'accès à Shodan, Censys ou Fofa (gratuite limitée ou "
                "payante), à écrire dans le fichier de réglages d'uncover")
        source = "Shodan InternetDB (gratuit, sans clé)"
        for ip in ips[:4]:
            libre = outils.executer_detail("uncover", ["-e", "shodan-idb", "-q", ip,
                                                       "-silent", "-l", "100"], delai=120)
            services += [s for s in lire_uncover(libre.stdout) if s not in services]
    ports = sorted({s.rsplit(":", 1)[1] for s in services}, key=int)
    brut = {"services": len(services), "ports": ports, "source": source}
    if not services:
        return [Constat(BLOC, OK, "Rien d'indexé par Shodan et Censys au nom du domaine",
                        "Les moteurs qui recensent les machines visibles sur internet ne "
                        "citent pas ce domaine.", cle="moteurs_exposition")], brut
    return [Constat(
        BLOC, INFO, f"{len(services)} services liés au domaine déjà recensés par Shodan/Censys",
        "Ces moteurs photographient en permanence les machines visibles sur internet ; "
        "les pirates s'en servent pour choisir leurs cibles. Ports vus : "
        + ", ".join(ports[:15]) + ". Certains peuvent appartenir à l'hébergeur : à trier "
        "à la relecture.",
        "Fermer ce qui n'a pas besoin d'être visible depuis internet.",
        cle="moteurs_exposition", hors_note=True)], brut


# ---------------------------------------------------------------------------
# Metagoofil : documents de la société trouvés par les moteurs de recherche, puis lus
# par ExifTool (noms COMPTÉS, jamais listés).

TYPES_DOCUMENTS = "pdf,doc,docx,xls,xlsx,ppt,pptx,odt,ods"


def analyser_metagoofil(cible):
    with tempfile.TemporaryDirectory() as dossier:
        documents = os.path.join(dossier, "documents")
        os.makedirs(documents)
        resultat = outils.executer_detail(
            "metagoofil", ["-d", cible.domaine, "-t", TYPES_DOCUMENTS, "-l", "40", "-n", "10",
                           "-o", documents, "-w"], delai=420, dossier=dossier)
        fichiers = [f for f in os.listdir(documents)
                    if os.path.isfile(os.path.join(documents, f))]
        if not fichiers:
            if re.search(r"429|too many requests|captcha", resultat.stdout + resultat.stderr, re.I):
                raise ControleImpossible("Google a bloqué la recherche (trop de questions) : "
                                         "réessayer plus tard")
            return [Constat(BLOC, OK, "Aucun document de la société trouvé par Google",
                            "Les moteurs de recherche ne référencent aucun PDF, Word ou "
                            "Excel publié sur ce domaine.", cle="documents_google")], \
                {"documents": 0}
        if not outils.disponible("exiftool"):
            return [Constat(BLOC, INFO, f"{len(fichiers)} documents de la société référencés "
                                        "par Google",
                            "Ils sont publics. ExifTool n'étant pas installé, leurs "
                            "informations cachées n'ont pas été lues.",
                            cle="documents_google", hors_note=True)], {"documents": len(fichiers)}
        infos = metadonnees.lire_sortie(outils.executer(
            "exiftool", ["-json", "-G", "-n", "-q", "-q", documents], delai=120))
    constats = []
    if infos["noms"]:
        constats.append(Constat(
            BLOC, INFO, f"Les documents trouvés par Google révèlent {infos['noms']} noms de "
                        "personnes",
            f"{infos['fichiers']} documents publics lus. Ces noms servent aux escrocs pour "
            "écrire des mails piégés crédibles. Le diagnostic ne les liste pas.",
            "Effacer l'auteur des documents avant de les publier.",
            cle="noms_documents_google"))
    if infos["logiciels"]:
        constats.append(Constat(
            BLOC, INFO, "Les documents trouvés par Google révèlent les logiciels utilisés",
            "Logiciels visibles : " + ", ".join(infos["logiciels"][:6]) + ".",
            "Nettoyer les informations des fichiers avant de les publier.",
            cle="logiciels_documents_google", hors_note=True))
    if not constats:
        constats.append(Constat(
            BLOC, OK, f"Aucune information cachée dans {infos['fichiers']} documents trouvés "
                      "par Google", "Ni nom, ni logiciel dans ces documents.",
            cle="documents_google"))
    return constats, {"documents": infos}


# ---------------------------------------------------------------------------
# Exiv2 : position GPS dans les photos de la page d'accueil (2e avis d'ExifTool).

def lire_exiv2(texte):
    """(position GPS ?, auteur noté ?) pour UNE photo, d'après « exiv2 -pa »."""
    gps = bool(re.search(r"GPSInfo\.GPS(Latitude|Longitude)\s", texte or ""))
    auteur = bool(re.search(r"Exif\.Image\.(Artist|XPAuthor)\s+\S+\s+\d+\s+\S", texte or ""))
    return gps, auteur


def analyser_exiv2(cible):
    accueil = indices.page(cible.domaine)
    if accueil is None:
        raise ControleImpossible("la page d'accueil ne répond pas : aucune photo à lire")
    base = _url(cible) + "/"
    photos = [u for u in metadonnees.liens_fichiers(accueil, base, cible.domaine)
              if metadonnees.IMAGE.search(urllib.parse.urlparse(u).path)][:10]
    if not photos:
        return [], {"photos": 0}
    avec_gps, avec_auteur, lues = 0, 0, 0
    with tempfile.TemporaryDirectory() as dossier:
        for numero, url in enumerate(photos):
            try:
                contenu = metadonnees._ouvrir(url)
            except Exception:
                continue
            chemin = os.path.join(dossier, f"photo{numero:02d}" +
                                  os.path.splitext(urllib.parse.urlparse(url).path)[1][:6])
            with open(chemin, "wb") as fichier:
                fichier.write(contenu)
            gps, auteur = lire_exiv2(outils.executer("exiv2", ["-q", "-pa", chemin], delai=30))
            lues += 1
            avec_gps += gps
            avec_auteur += auteur
    brut = {"photos": lues, "avec_gps": avec_gps, "avec_auteur": avec_auteur}
    if not lues:
        raise ControleImpossible("aucune photo de la page d'accueil n'a pu être téléchargée")
    if avec_gps:
        return [Constat(
            BLOC, IMPORTANT, f"{avec_gps} photos publiées donnent une position GPS",
            "Ces photos indiquent l'endroit exact où elles ont été prises : parfois un "
            "domicile ou un local que la société ne souhaite pas rendre public.",
            "Retirer la position des photos avant de les publier.", cle="gps")], brut
    return [Constat(BLOC, OK, f"Aucune position GPS dans {lues} photos de la page d'accueil",
                    "Les photos publiées ne disent pas où elles ont été prises.",
                    cle="gps")], brut


# ---------------------------------------------------------------------------
# Instaloader : la fiche publique du compte Instagram que la société affiche sur son site.

def lire_instagram(data):
    noeud = (data or {}).get("node", data or {})
    return {
        "abonnes": ((noeud.get("edge_followed_by") or {}).get("count")),
        "prive": bool(noeud.get("is_private")),
        "professionnel": bool(noeud.get("is_business_account")),
        "contact_public": bool(noeud.get("business_email") or noeud.get("business_phone_number")),
    }


def analyser_instaloader(cible):
    comptes = indices.comptes_societe(cible.domaine).get("instagram") or []
    if not comptes:
        raise ControleImpossible("le site n'affiche aucun compte Instagram : rien à lire")
    compte = comptes[0]
    with tempfile.TemporaryDirectory() as dossier:
        resultat = outils.executer_detail(
            "instaloader", ["--no-pictures", "--no-videos", "--no-video-thumbnails",
                            "--no-captions", "--no-posts", "--no-profile-pic",
                            "--no-compress-json", "--quiet", "--dirname-pattern",
                            os.path.join(dossier, "{profile}"), "--", compte],
            delai=180, dossier=dossier)
        fiche = None
        for chemin in glob.glob(os.path.join(dossier, "**", "*.json"), recursive=True):
            try:
                with open(chemin, encoding="utf-8") as lu:
                    data = json.load(lu)
            except (OSError, json.JSONDecodeError):
                continue
            if "node" in data or "edge_followed_by" in data:
                fiche = lire_instagram(data)
                break
    messages = resultat.stdout + resultat.stderr
    if fiche is None:
        if re.search(r"unrecognized arguments", messages):
            raise ControleImpossible("Instaloader est trop ancien : le mettre à jour")
        if re.search(r"login|401|please wait|429|redirected", messages, re.I):
            raise ControleImpossible("Instagram refuse la lecture sans connexion pour "
                                     "l'instant (limite anti-robots) : réessayer plus tard")
        if resultat.returncode:
            raise ControleImpossible("Instaloader n'a pas pu lire le compte ("
                                     + _derniere_ligne(messages) + ")")
        fiche = {}
    texte = f"Compte affiché sur le site : @{compte}."
    if fiche.get("abonnes") is not None:
        texte += f" {fiche['abonnes']} abonnés."
    if fiche.get("contact_public"):
        texte += (" Il affiche publiquement un e-mail ou un téléphone de contact (non "
                  "recopié ici) : pratique pour les clients, mais aussi pour les escrocs.")
    return [Constat(BLOC, INFO, "Compte Instagram public de la société",
                    texte, cle="instagram", hors_note=True)], {"instagram": fiche}


# ---------------------------------------------------------------------------
# Sherlock, Maigret, user-scanner, Social Analyzer sur le NOM de la société (sa marque).
# Ce n'est pas une recherche sur une personne : les comptes du dirigeant restent soumis
# à son accord écrit (module pseudos). Si le domaine porte le nom d'une personne
# (entreprise individuelle), Anass écarte ce point à la relecture.

def analyser_pseudos_societe(cible):
    candidats = indices.pseudos_societe(cible.domaine)
    if not candidats:
        raise ControleImpossible("aucun nom de société exploitable comme pseudo")
    installes = [(nom, fonction) for nom, commande, fonction in pseudos.OUTILS
                 if outils.disponible(commande)]
    if not installes:
        raise ControleImpossible("aucun outil de recherche de pseudo installé (Sherlock…)")
    constats, brut = [], {}
    for pseudo in candidats:
        # Les quatre outils en même temps, 5 minutes au plus chacun (pseudos.DELAI_OUTIL).
        par_outil, ecartes = pseudos.lancer_ensemble(pseudo, installes)
        sites = pseudos.recouper(par_outil)
        exiges = 2 if len(par_outil) > 1 else 1
        probables = sorted(s["site"] for s in sites.values() if len(s["vu_par"]) >= exiges)
        brut[pseudo] = {"par_outil": {n: len(c) for n, c in par_outil.items()},
                        "probables": probables, "ecartes": ecartes}
        if not probables:
            continue
        constats.append(Constat(
            BLOC, INFO, f"Le nom « {pseudo} » est déjà pris sur {len(probables)} sites",
            "Sites : " + ", ".join(probables[:20])
            + (" et d'autres" if len(probables) > 20 else "") + ". Outils : "
            + ", ".join(f"{n} ({len(c)})" for n, c in par_outil.items()) + ". Vérifiez que "
            "ces comptes sont bien les vôtres : un compte à votre nom tenu par un inconnu "
            "peut servir à se faire passer pour la société.",
            "Réserver le nom de la société sur les grands réseaux, même sans s'en servir.",
            cle=f"marque_{pseudo.lower()}", hors_note=True))
    if not constats:
        constats.append(Constat(BLOC, OK, "Le nom de la société n'est pris sur aucun autre site",
                                "Aucun compte à ce nom n'a été trouvé par plusieurs outils.",
                                cle="marque"))
    return constats, brut


# ---------------------------------------------------------------------------
# PhoneInfoga sur les numéros AFFICHÉS par la société (jamais recopiés dans le rapport).

def analyser_phoneinfoga(cible):
    numeros = indices.numeros_publics(cible.domaine)
    if not numeros:
        raise ControleImpossible("le site n'affiche aucun numéro de téléphone : rien à analyser")
    fiches = []
    for numero in numeros:
        infos = telephone.lire_phoneinfoga(outils.executer(
            "phoneinfoga", ["scan", "-n", numero, "-D", "numverify", "-D", "googlecse"],
            delai=180))
        fiches.append({"pays": infos.get("Country") or "inconnu",
                       "portable": bool(telephone.portables("0" + numero[-9:])),
                       "recherches": len(infos.get("recherches", []))})
    portables = sum(f["portable"] for f in fiches)
    recherches = sum(f["recherches"] for f in fiches)
    return [Constat(
        BLOC, INFO, f"{len(fiches)} numéros affichés sur le site analysés par PhoneInfoga",
        f"Dont {portables} portables. Pays : "
        + ", ".join(sorted({f['pays'] for f in fiches})) + f". {recherches} recherches "
        "publiques sont prêtes pour la relecture (réseaux sociaux, annuaires). Les numéros "
        "ne sont pas recopiés dans ce rapport.",
        "Protéger les lignes mobiles par un code auprès de l'opérateur." if portables else "",
        cle="numeros_phoneinfoga", hors_note=True)], {"numeros": fiches}


# ---------------------------------------------------------------------------
# ArchiveBox : copie datée de la page d'accueil, gardée sur l'ordinateur d'Anass.

def analyser_archivebox(cible):
    dossier = os.path.join(TRAVAIL, "archivebox")
    os.makedirs(dossier, exist_ok=True)
    if not os.path.exists(os.path.join(dossier, "index.sqlite3")):
        init = outils.executer_detail("archivebox", ["init"], delai=300, dossier=dossier)
        if init.returncode and not os.path.exists(os.path.join(dossier, "index.sqlite3")):
            raise ControleImpossible("ArchiveBox n'a pas pu créer son dossier d'archives ("
                                     + _derniere_ligne(init.stderr or init.stdout) + ")")
    ajout = outils.executer_detail("archivebox", ["add", "--depth=0", _url(cible)],
                                   delai=600, dossier=dossier)
    if ajout.returncode:
        raise ControleImpossible("ArchiveBox n'a pas pu archiver la page ("
                                 + _derniere_ligne(ajout.stderr or ajout.stdout) + ")")
    return [Constat(BLOC, OK, "Copie datée de la page d'accueil gardée (ArchiveBox)",
                    "Vigie garde la page telle qu'elle était le jour du diagnostic, pour "
                    "comparer après la sécurisation.", cle="archive_page",
                    hors_note=True)], {"dossier": dossier}


# ---------------------------------------------------------------------------
# GHunt : seulement l'adresse DONNÉE par le dirigeant, avec son accord écrit.

def analyser_ghunt(cible):
    if not cible.emails:
        raise ControleImpossible("ne tourne que sur l'adresse Gmail donnée par le dirigeant, "
                                 "avec son accord écrit")
    if not cible.accord_dirigeant:
        raise ControleImpossible("accord écrit du dirigeant requis")
    constats, brut = [], {}
    for adresse in cible.emails:
        with tempfile.TemporaryDirectory() as dossier:
            chemin = os.path.join(dossier, "ghunt.json")
            resultat = outils.executer_detail("ghunt", ["email", adresse, "--json", chemin],
                                              delai=180, dossier=dossier)
            if not os.path.exists(chemin):
                if re.search(r"login|cookies|credentials", resultat.stdout + resultat.stderr, re.I):
                    raise ControleImpossible("GHunt doit d'abord être relié une fois à un "
                                             "compte Google (commande « ghunt login »)")
                brut[adresse] = {"compte_google": False}
                continue
        brut[adresse] = {"compte_google": True}
        constats.append(Constat(
            BLOC, INFO, "Un compte Google est rattaché à l'adresse du dirigeant",
            "Google montre publiquement certaines informations de ce compte (photo, avis "
            "laissés sur Maps, agendas publics). À relire avec le dirigeant.",
            "Vérifier les réglages de confidentialité du compte Google.",
            cle="google_dirigeant", hors_note=True))
    return constats, brut
