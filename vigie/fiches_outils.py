"""La fiche « en clair » de chaque outil lançable seul : à quoi il sert, ce qu'il attend.

But : quand Anass lance un outil depuis « Lancer un outil », il doit comprendre tout
seul, en français, pourquoi ça marche ou pourquoi ça ne marche pas. Pour ça, Vigie
doit savoir, pour chaque outil :
  - à quoi il sert (une phrase simple) ;
  - quel genre de cible il attend (domaine, adresse de site, pseudo, e-mail,
    téléphone, fichier, dossier… ou aucune) ;
  - s'il se lance vraiment « sur une cible » ou si c'est autre chose : un service qui
    tourne en permanence (AdGuard Home), un logiciel à fenêtres (Ghidra), un outil
    Windows, une capture réseau, un jeu de règles, un outil qui demande un compte…
  - éventuellement la bonne ligne de lancement, quand celle devinée du catalogue
    est fausse.

Ce fichier ne lance rien : il décrit. lancer_seul.py s'en sert pour vérifier la cible
AVANT de lancer, et expliquer en français si elle ne colle pas.
"""
import ipaddress
import os
import re

from . import spiderfoot

# ---------------------------------------------------------------------------
# Les genres de cible, avec un exemple pour guider.
CIBLES = {
    "domaine": ("un nom de domaine", "exemple.fr"),
    "url": ("l'adresse d'un site", "https://exemple.fr"),
    "pseudo": ("un pseudo", "jean_dupont"),
    "email": ("une adresse e-mail", "contact@exemple.fr"),
    "telephone": ("un numéro de téléphone", "+33612345678"),
    "fichier": ("un fichier sur cet ordinateur", "/home/moi/photo.jpg"),
    "dossier": ("un dossier sur cet ordinateur", "/home/moi/projet"),
    "aucune": ("rien (il analyse cet ordinateur)", ""),
}

# Les façons dont un outil peut (ou non) se lancer depuis Vigie.
#   cible      : une commande sur une cible -> Vigie le lance.
#   service    : un serveur qui tourne en permanence -> à installer, pas à « lancer ».
#   appli      : un logiciel à fenêtres ou une appli web -> on l'ouvre à la main.
#   windows    : ne tourne que sous Windows.
#   capture    : écoute une carte réseau, droits administrateur -> à la main.
#   ressource  : pas un programme, des règles/configs pour un autre outil.
#   compte     : demande un compte ou une clé avant tout lancement.
#   a_la_main  : demande une préparation (règles, configuration…) -> à la main.
#   agent      : une compétence pour assistant IA, pas un programme.
MODES = ("cible", "service", "appli", "windows", "capture", "ressource", "compte",
         "a_la_main", "agent")


def _f(role, cible="aucune", mode="cible", prealable="", ligne=None, delai=None):
    """delai : temps maximum en secondes, pour un outil plus long que les 5 minutes
    habituelles (SpiderFoot interroge 25 sources) ; au-delà, Vigie l'arrête et garde
    ce qu'il a déjà trouvé."""
    return {"role": role, "cible": cible, "mode": mode, "prealable": prealable,
            "ligne": ligne, "delai": delai}


# Clé = nom du registre en minuscules.
FICHES = {
    # --- OSINT : pseudos, e-mails, téléphones -------------------------------
    "sherlock": _f("cherche sur quels sites (réseaux sociaux, forums…) un pseudo existe",
                   "pseudo"),
    "maigret": _f("cherche un pseudo sur des milliers de sites et rassemble ce qui est "
                  "public sur la personne", "pseudo"),
    "social analyzer": _f("cherche un pseudo sur les réseaux sociaux et évalue si les "
                          "profils trouvés sont bien la même personne", "pseudo"),
    "user-scanner": _f("vérifie sur quels sites un pseudo est déjà pris", "pseudo",
                       ligne=["user-scanner", "-u", "{cible}"]),
    "instaloader": _f("télécharge les photos et infos publiques d'un compte Instagram",
                      "pseudo"),
    "holehe": _f("vérifie sur quels sites une adresse e-mail a servi à créer un compte",
                 "email"),
    "ghunt": _f("cherche ce que Google montre publiquement sur une adresse Gmail",
                "email", "compte",
                "il faut d'abord se connecter une fois avec un compte Google "
                "(commande « ghunt login »)"),
    "toutatis": _f("extrait l'e-mail et le téléphone partiels d'un compte Instagram",
                   "pseudo", "compte",
                   "il faut un identifiant de session Instagram (être connecté à un compte "
                   "Instagram), ce que Vigie ne fait pas"),
    "phoneinfoga": _f("dit à quel opérateur et à quel pays appartient un numéro de "
                      "téléphone, et cherche ses traces publiques", "telephone"),
    # --- OSINT : domaines et sites ------------------------------------------
    "theharvester": _f("cherche les adresses e-mail et sous-domaines publics d'un domaine",
                       "domaine"),
    "metagoofil": _f("cherche les documents publics (PDF, Word, Excel) d'un domaine",
                     "domaine", ligne=["metagoofil", "-d", "{cible}", "-t", "pdf,doc,xls"]),
    "owasp amass": _f("liste les sous-domaines d'un domaine", "domaine"),
    "subfinder": _f("liste les sous-domaines d'un domaine à partir de sources publiques",
                    "domaine"),
    "dnstwist": _f("cherche les faux domaines qui imitent le vôtre (typosquatting)",
                   "domaine"),
    "dnsrecon": _f("lit les réglages DNS publics d'un domaine", "domaine"),
    "dnsx": _f("vérifie quels noms d'un domaine répondent vraiment", "domaine"),
    "checkdmarc": _f("vérifie si les e-mails d'un domaine peuvent être usurpés "
                     "(SPF, DMARC)", "domaine"),
    "gau": _f("retrouve les anciennes adresses de pages d'un site dans les archives "
              "d'Internet", "domaine"),
    "httpx": _f("vérifie si un site répond et relève son titre et sa technologie", "url"),
    "whatweb": _f("reconnaît les technologies d'un site (WordPress, serveur…)", "url"),
    "arjun": _f("découvre les paramètres cachés qu'une page accepte (utile pour trouver "
                "des entrées oubliées sur un endpoint)", "url",
                ligne=["arjun", "-u", "{cible}", "--stable"]),
    # SpiderFoot : 25 sources publiques choisies par Vigie (spiderfoot.py), sortie JSON
    # traduite. Son interface web s'ouvre aussi depuis « Ouvrir un outil ».
    "spiderfoot": _f("rassemble en un seul passage ce que 25 sources publiques savent d'un "
                     "domaine : sous-domaines, adresses, hébergeur, faux domaines qui "
                     "l'imitent, listes noires, certificat", "domaine",
                     ligne=spiderfoot.ligne(), delai=spiderfoot.DELAI),
    # --- Scanners web (actifs/offensifs : seulement sur tes propres cibles) --
    "nikto": _f("cherche sur un serveur web les fichiers dangereux et les logiciels "
                "périmés", "url", ligne=["nikto", "-h", "{cible}"]),
    "wapiti": _f("teste un site à la recherche de failles web (formulaires, pages)",
                 "url", ligne=["wapiti", "-u", "{cible}"]),
    "katana": _f("parcourt un site pour lister toutes ses pages et points d'entrée",
                 "url", ligne=["katana", "-u", "{cible}"]),
    "dalfox": _f("cherche les failles d'injection de script (XSS) sur une page", "url",
                 ligne=["dalfox", "url", "{cible}"]),
    "xsstrike": _f("cherche les failles d'injection de script (XSS) sur une page, en "
                   "analysant comment elle renvoie ce qu'on lui envoie", "url",
                   ligne=["xsstrike", "-u", "{cible}"]),
    "dirsearch": _f("cherche les dossiers et fichiers cachés d'un site (pages d'admin, "
                    "sauvegardes oubliées…)", "url", ligne=["dirsearch", "-u", "{cible}"]),
    "sqlmap": _f("teste si une page est vulnérable à l'injection SQL (vol de base de "
                 "données)", "url", ligne=["sqlmap", "-u", "{cible}", "--batch"]),
    "cewl": _f("construit une liste de mots à partir du contenu d'un site (utile pour "
               "tester la robustesse des mots de passe)", "url",
               ligne=["cewl", "-d", "2", "-m", "5", "{cible}"]),
    "tlsx": _f("lit et analyse le certificat de sécurité (HTTPS) d'un domaine", "domaine",
               ligne=["tlsx", "-u", "{cible}", "-san", "-cn", "-silent"]),
    "wpprobe": _f("repère les extensions et thèmes WordPress d'un site et leurs failles "
                  "connues", "url", ligne=["wpprobe", "scan", "-u", "{cible}"]),
    "lighthouse": _f("note la qualité d'un site : vitesse, bonnes pratiques, protections",
                     "url", prealable="Google Chrome ou Chromium doit être installé"),
    "unlighthouse": _f("passe Lighthouse sur toutes les pages d'un site", "url",
                       prealable="Google Chrome ou Chromium doit être installé"),
    "sitespeed.io": _f("mesure la vitesse d'un site", "url",
                       prealable="Google Chrome ou Firefox doit être installé"),
    "pa11y": _f("vérifie si un site est accessible aux personnes handicapées", "url",
                prealable="Google Chrome ou Chromium doit être installé"),
    "linkchecker": _f("cherche les liens cassés d'un site", "url"),
    "gowitness": _f("prend une capture d'écran d'un site", "url",
                    prealable="Google Chrome ou Chromium doit être installé"),
    "sslyze": _f("vérifie la qualité du chiffrement (cadenas HTTPS) d'un site", "domaine",
                 ligne=["sslyze", "{cible}"]),
    "eyewitness": _f("prend des captures d'écran d'une liste de sites", "url", "a_la_main",
                     "il se lance depuis son propre dossier (script EyeWitness.py) avec une "
                     "liste de sites ; gowitness fait la même chose et se lance d'ici"),
    # --- OSINT : fichiers -----------------------------------------------------
    "exiftool": _f("lit les informations cachées d'une photo ou d'un document (auteur, "
                   "lieu GPS, logiciel…)", "fichier"),
    "exiv2": _f("lit les informations cachées d'une photo", "fichier"),
    # --- OSINT : à préparer ou à ouvrir à la main ---------------------------
    "archivebox": _f("garde une copie d'archive d'une page web", "url", "a_la_main",
                     "il faut d'abord créer un dossier d'archives (commande « archivebox "
                     "init » dans un dossier vide), puis lui donner une adresse de site "
                     "complète. Ce n'est pas un outil de recherche de pseudo"),
    "auto-archiver": _f("archive des pages web en série depuis un tableau", "url",
                        "a_la_main", "il faut d'abord écrire son fichier de configuration "
                        "(orchestration.yaml)"),
    "datashare": _f("range et fouille VOS propres documents", "aucune", "appli",
                    "c'est une application de bureau qu'on ouvre et qu'on remplit avec ses "
                    "documents"),
    "invid-weverify": _f("vérifie si une photo ou une vidéo est truquée ou déjà publiée",
                         "aucune", "appli", "c'est une extension du navigateur web"),
    "flowsint": _f("dessine un schéma d'enquête OSINT (qui est relié à quoi)", "aucune",
                   "appli", "c'est une plateforme web qu'on installe puis qu'on ouvre "
                   "dans le navigateur"),
    "geo-sleuth": _f("aide une IA à deviner où une photo a été prise", "aucune", "agent",
                     "c'est une compétence pour assistant IA (Claude Code, Cursor…), pas un "
                     "programme qu'on lance"),
    "web-check": _f("fait le tour d'un site (DNS, certificat, en-têtes…) dans une page web",
                    "aucune", "appli", "c'est une appli web : on l'ouvre dans le navigateur "
                    "et on tape l'adresse du site"),
    "ivre": _f("cartographie un réseau à partir de scans", "aucune", "service",
               "c'est une plateforme complète (base de données + interface web) à "
               "installer et à alimenter avec des scans"),
    # --- Sécurisation : sur cet ordinateur ---------------------------------
    "lynis": _f("audite la sécurité de CET ordinateur (Linux ou Mac) et donne des conseils",
                "aucune", ligne=["lynis", "audit", "system", "--quick", "--no-colors"]),
    "clamav": _f("cherche des virus dans un fichier ou un dossier", "dossier",
                 ligne=["clamscan", "-r", "--infected", "{cible}"]),
    "semgrep": _f("relit du code source pour y trouver des failles", "dossier",
                  ligne=["semgrep", "scan", "--config", "auto", "{cible}"]),
    "skillspector": _f("vérifie la sécurité d'une « compétence » d'assistant IA", "dossier",
                       ligne=["skillspector", "scan", "{cible}"]),
    "the sleuth kit": _f("liste les fichiers (même effacés) d'une image de disque",
                         "fichier", ligne=["fls", "-r", "{cible}"]),
    "volatility 3": _f("analyse une copie de la mémoire vive d'un ordinateur (enquête "
                       "après incident)", "fichier",
                       ligne=["vol", "-f", "{cible}", "windows.info"]),
    "yara": _f("cherche des virus connus avec des règles de détection", "dossier",
               "a_la_main", "il faut lui donner un fichier de règles (.yar) en plus du "
               "dossier à fouiller"),
    "plaso (log2timeline)": _f("reconstitue la chronologie d'un incident à partir d'une "
                               "image de disque", "fichier", "a_la_main",
                               "l'analyse dure des heures et produit un gros fichier ; "
                               "à lancer à la main sur une enquête réelle"),
    "zircolite": _f("cherche des traces d'attaque dans les journaux Windows", "dossier",
                    "a_la_main", "il faut lui donner des règles Sigma en plus des journaux"),
    "chainsaw": _f("cherche des traces d'attaque dans les journaux Windows", "dossier",
                   "a_la_main", "il faut lui donner des règles Sigma et un fichier de "
                   "correspondance en plus des journaux"),
    "hayabusa": _f("fait la chronologie des événements de journaux Windows", "dossier",
                   "a_la_main", "au premier lancement il pose des questions (mise à jour "
                   "des règles) : à faire une fois à la main"),
    "sigwood": _f("fouille les journaux d'un serveur pour repérer des attaques", "dossier",
                  "a_la_main", "il faut lui indiquer quels journaux lire"),
    "radare2": _f("désassemble un programme pour comprendre ce qu'il fait", "fichier",
                  "appli", "on s'en sert en tapant des commandes dans sa propre console"),
    "osquery": _f("interroge l'ordinateur comme une base de données (programmes, "
                  "connexions…)", "aucune", "appli",
                  "on s'en sert en tapant des requêtes dans sa propre console"),
    "garak": _f("teste si une IA (chatbot) peut être piégée", "aucune", "compte",
                "il faut choisir le modèle d'IA à tester et souvent une clé d'accès à ce "
                "modèle"),
    "vulnhuntr": _f("relit du code Python avec une IA pour y trouver des failles",
                    "dossier", "compte", "il faut une clé d'accès à une IA (Claude, GPT…)"),
    # --- Sécurisation : capture réseau --------------------------------------
    "tcpdump": _f("enregistre le trafic qui passe sur une carte réseau", "aucune",
                  "capture"),
    "wireshark": _f("enregistre et décode le trafic réseau, avec une fenêtre", "aucune",
                    "capture"),
    "kismet": _f("détecte les réseaux Wi-Fi et appareils sans fil alentour", "aucune",
                 "capture"),
    "sparrow-wifi": _f("analyse les réseaux Wi-Fi et Bluetooth alentour, avec une fenêtre",
                       "aucune", "capture"),
    "suricata": _f("détecte les attaques dans le trafic réseau (alarme réseau)", "aucune",
                   "capture"),
    "snort 3": _f("détecte les attaques dans le trafic réseau (alarme réseau)", "aucune",
                  "capture"),
    "zeek": _f("observe le trafic réseau et en tient un journal détaillé", "aucune",
               "capture"),
    "ntopng (community)": _f("montre qui consomme quoi sur le réseau, dans une page web",
                             "aucune", "capture"),
    "arkime": _f("enregistre tout le trafic réseau pour pouvoir le fouiller plus tard",
                 "aucune", "service", "c'est une plateforme lourde (capture + base de "
                 "données + interface web)"),
    # --- Sécurisation : services qui tournent en permanence -----------------
    "adguard home": _f("filtre les publicités et sites dangereux pour tout un réseau "
                       "(serveur DNS filtrant)", "aucune", "service"),
    "pi-hole": _f("filtre les publicités et sites dangereux pour tout un réseau "
                  "(serveur DNS filtrant)", "aucune", "service"),
    "fail2ban": _f("bloque automatiquement les adresses qui essaient trop de mots de passe "
                   "sur un serveur", "aucune", "service"),
    "crowdsec": _f("bloque les attaquants connus grâce à une liste partagée", "aucune",
                   "service"),
    "wazuh": _f("surveille tout un parc d'ordinateurs et alerte en cas d'attaque",
                "aucune", "service"),
    "uptime kuma": _f("surveille si des sites ou serveurs restent en ligne", "aucune",
                      "service"),
    "misp": _f("partage des informations sur les menaces entre équipes", "aucune",
               "service"),
    "cowrie": _f("fait semblant d'être un serveur (pot de miel) pour enregistrer les attaquants", "aucune",
                 "service"),
    "opencanary": _f("imite des services (pot de miel) et alerte dès qu'on les touche",
                     "aucune", "service"),
    "gophish": _f("organise de fausses campagnes d'hameçonnage pour former le personnel",
                  "aucune", "service"),
    "falco": _f("surveille en direct ce que font les programmes d'un serveur", "aucune",
                "service"),
    "grr rapid response": _f("enquête à distance sur un parc d'ordinateurs", "aucune",
                             "service"),
    "velociraptor": _f("enquête à distance sur un parc d'ordinateurs", "aucune", "service"),
    "deepaudit": _f("fait relire du code par plusieurs IA", "aucune", "service"),
    "open-kritt": _f("fait chercher des failles dans du code par des IA", "aucune",
                     "service"),
    "coraza waf": _f("protège un site web des attaques (pare-feu web)", "aucune", "service"),
    "caddy waf": _f("sert des sites web avec HTTPS automatique et un pare-feu", "aucune", "service"),
    "pfsense ce": _f("protège et relie tout un réseau (pare-feu et routeur)", "aucune", "service",
                     "c'est un système complet à installer sur une machine dédiée"),
    "opnsense": _f("protège et relie tout un réseau (pare-feu et routeur)", "aucune", "service",
                   "c'est un système complet à installer sur une machine dédiée"),
    # --- Sécurisation : logiciels à fenêtres --------------------------------
    "ghidra": _f("désassemble un programme pour comprendre ce qu'il fait", "aucune",
                 "appli"),
    "autopsy": _f("enquête sur le contenu d'un disque dur", "aucune", "appli"),
    "cyberchef": _f("décode ou transforme des données (couteau suisse)", "aucune",
                    "appli", "c'est une page web qu'on ouvre dans le navigateur"),
    "veracrypt": _f("crée des coffres chiffrés pour protéger des fichiers", "aucune",
                    "appli"),
    # --- Sécurisation : Windows seulement -----------------------------------
    "hardeningkitty": _f("vérifie les réglages de sécurité d'un PC Windows", "aucune",
                         "windows"),
    "harden-windows-security": _f("durcit les réglages de sécurité d'un PC Windows",
                                  "aucune", "windows"),
    "hardentools": _f("désactive les fonctions Windows à risque (macros Office…)",
                      "aucune", "windows"),
    "outils zimmerman": _f("lit les traces laissées sur un PC Windows (enquête)", "aucune",
                           "windows"),
    # --- Sécurisation : des règles, pas des programmes ----------------------
    "sigma": _f("décrit des attaques à repérer dans des journaux", "aucune",
                "ressource", "on les charge dans un outil comme Zircolite, Chainsaw ou un "
                "SIEM"),
    "owasp crs": _f("bloque les attaques web courantes", "aucune", "ressource",
                    "on les charge dans un pare-feu web (ModSecurity, Coraza)"),
    "devsec hardening": _f("durcit des serveurs automatiquement (recettes toutes prêtes)", "aucune",
                           "ressource", "on les applique avec Ansible, Chef ou Puppet"),
    "sysmon-modular": _f("règle Windows pour qu'il garde un journal détaillé", "aucune",
                         "ressource", "on les charge dans Sysmon, sous Windows"),
}


def fiche(nom, registre_fiche=None):
    """La fiche en clair d'un outil. Pour un outil sans fiche écrite, une fiche prudente
    déduite du catalogue (rôle = sa catégorie, cible inconnue)."""
    cle = (nom or "").strip().lower()
    if cle in FICHES:
        return dict(FICHES[cle])
    role = ""
    if registre_fiche:
        role = (registre_fiche.get("categorie") or "").lower()
    return _f(role or "outil du catalogue", "inconnue")


# ---------------------------------------------------------------------------
# Reconnaître ce que la personne a tapé.
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_DOMAINE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                      r"[A-Za-z]{2,}$")
_TELEPHONE = re.compile(r"^\+?[\d][\d .()-]{6,}$")
_PSEUDO = re.compile(r"^@?[\w.-]{1,60}$")


def type_de(cible):
    """Ce que ressemble la cible tapée : url, email, telephone, ip, chemin, domaine,
    pseudo ou texte."""
    c = (cible or "").strip()
    if re.match(r"^https?://", c, re.I):
        return "url"
    if _EMAIL.match(c):
        return "email"
    try:
        ipaddress.ip_address(c)
        return "ip"
    except ValueError:
        pass
    if _TELEPHONE.match(c) and sum(ch.isdigit() for ch in c) >= 8:
        return "telephone"
    if c.startswith(("/", "~", "./", "../")) or "\\" in c:
        return "chemin"
    if _DOMAINE.match(c):
        return "domaine"
    if _PSEUDO.match(c):
        return "pseudo"
    return "texte"


_NOMS_TYPES = {
    "url": "une adresse de site", "email": "une adresse e-mail", "ip": "une adresse IP",
    "telephone": "un numéro de téléphone", "chemin": "un chemin de fichier",
    "domaine": "un nom de domaine", "pseudo": "un pseudo", "texte": "du texte libre",
}


class CibleInadaptee(ValueError):
    """La cible ne correspond pas à ce que l'outil attend. Le message est en français."""


def _hote(url):
    return re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0]


def adapter_cible(nom, cible, fiche_outil):
    """Vérifie la cible pour cet outil, et l'arrange quand c'est sans risque.

    Renvoie (cible à utiliser, remarque en français ou ""). Lève CibleInadaptee avec
    une explication en français si la cible ne peut pas convenir.
    """
    attendu = fiche_outil.get("cible", "inconnue")
    cible = (cible or "").strip()
    genre = type_de(cible)
    quoi, exemple = CIBLES.get(attendu, ("", ""))

    def refus(detail=""):
        texte = (f"{nom} attend {quoi} (par exemple : {exemple}). "
                 f"Tu as tapé « {cible} », qui ressemble à {_NOMS_TYPES[genre]}.")
        if detail:
            texte += " " + detail
        raise CibleInadaptee(texte)

    if attendu in ("inconnue", ""):
        return cible, ""
    if attendu == "aucune":
        if cible:
            return "", (f"{nom} n'a pas besoin de cible : il analyse cet ordinateur. "
                        f"« {cible} » est ignoré.")
        return "", ""
    if not cible:
        raise CibleInadaptee(f"{nom} attend {quoi} (par exemple : {exemple}).")
    if attendu == "domaine":
        if genre == "domaine":
            return cible.lower(), ""
        if genre == "url":
            hote = _hote(cible)
            if _DOMAINE.match(hote):
                return hote.lower(), (f"{nom} attend un nom de domaine : Vigie a gardé "
                                      f"« {hote} » de l'adresse tapée.")
        if genre == "email":
            refus(f"Pour le domaine de cette adresse, tape « {cible.split('@')[1]} ».")
        refus()
    if attendu == "url":
        if genre == "url":
            return cible, ""
        if genre in ("domaine", "ip"):
            return "https://" + cible, (f"{nom} attend l'adresse complète d'un site : "
                                        f"Vigie a ajouté « https:// » devant.")
        refus()
    if attendu == "pseudo":
        if genre in ("pseudo", "domaine"):     # un pseudo peut contenir un point
            return cible.lstrip("@"), ""
        refus("Un pseudo, c'est le nom d'utilisateur sur les réseaux (sans espace, "
              "sans « http »).")
    if attendu == "email":
        if genre == "email":
            return cible.lower(), ""
        refus()
    if attendu == "telephone":
        if genre == "telephone":
            chiffres = re.sub(r"[^\d+]", "", cible)
            if re.fullmatch(r"0\d{9}", chiffres):
                return "+33" + chiffres[1:], ("Numéro français : Vigie l'a écrit au "
                                              "format international (+33…).")
            return chiffres, ""
        refus()
    if attendu in ("fichier", "dossier"):
        chemin = os.path.abspath(os.path.expanduser(cible))
        if not os.path.exists(chemin):
            if genre in ("domaine", "url", "pseudo", "email", "telephone", "ip"):
                refus(f"Cet outil travaille sur {quoi}, pas sur Internet.")
            raise CibleInadaptee(
                f"{nom} attend {quoi}, mais « {cible} » n'existe pas sur cet ordinateur. "
                "Vérifie le chemin (astuce : glisse le fichier dans un terminal pour "
                "voir son chemin exact).")
        if attendu == "dossier" or os.path.isfile(chemin) or os.path.isdir(chemin):
            return chemin, ""
    return cible, ""


# ---------------------------------------------------------------------------
# Expliquer pourquoi un outil ne se lance pas « sur une cible ».
def explication_mode(nom, fiche_outil, cible=""):
    """Un texte en français si l'outil ne se lance pas depuis Vigie, sinon None."""
    mode = fiche_outil.get("mode", "cible")
    role = fiche_outil.get("role", "")
    prealable = fiche_outil.get("prealable", "")
    sur = f" sur « {cible} »" if cible else ""
    a_quoi = f"À quoi ça sert : ça {role}." if role else ""
    if mode == "cible":
        return None
    if mode == "service":
        texte = (f"{nom} ne se lance pas{sur} : ce n'est pas un outil d'analyse, c'est un "
                 "service qu'on installe et qui tourne en permanence sur une machine "
                 "(un serveur, une box, une machine virtuelle). "
                 f"{a_quoi} ")
        if prealable:
            texte += prealable[0].upper() + prealable[1:] + ". "
        texte += ("Pour Vigie, c'est un outil à conseiller à un client (offre "
                  "sécurisation), pas un outil de diagnostic.")
        return texte
    if mode == "appli":
        texte = (f"{nom} ne se lance pas depuis Vigie : c'est un logiciel qu'on ouvre et "
                 f"qu'on utilise soi-même, à la souris ou au clavier. {a_quoi} ")
        if prealable:
            texte += prealable[0].upper() + prealable[1:] + "."
        return texte.strip()
    if mode == "windows":
        return (f"{nom} ne fonctionne que sous Windows : il ne peut pas tourner sur cet "
                f"ordinateur (Linux ou Mac). {a_quoi} À utiliser sur un PC Windows, "
                "par exemple chez un client, en offre sécurisation.")
    if mode == "capture":
        return (f"{nom} ne se lance pas{sur} : il écoute le trafic d'une carte réseau "
                "(câble ou Wi-Fi). Il faut les droits administrateur et choisir la carte "
                "à écouter, et on ne l'utilise que sur SON propre réseau. "
                f"{a_quoi} À lancer à la main sur ton réseau.")
    if mode == "ressource":
        return (f"{nom} n'est pas un programme : ce sont des règles ou des réglages qu'on "
                f"charge dans un autre outil. {a_quoi} "
                + (prealable[0].upper() + prealable[1:] + "." if prealable else ""))
    if mode == "compte":
        return (f"{nom} ne peut pas partir tout seul : {prealable}. {a_quoi} "
                "Tant que ce n'est pas fait, Vigie ne le lance pas.")
    if mode == "agent":
        return f"{nom} ne se lance pas : {prealable}. {a_quoi}"
    # a_la_main
    return (f"{nom} demande une préparation avant de pouvoir être lancé : {prealable}. "
            f"{a_quoi} Vigie ne le lance donc pas tout seul pour l'instant.")
