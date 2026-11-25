"""Traduire en français simple les messages d'erreur (en anglais) des outils.

Les outils parlent anglais et technique (« Temporary failure in name resolution »,
« ModuleNotFoundError »…). Ici on reconnaît les messages les plus courants et on dit,
en une ou deux phrases, ce que ça veut dire et quoi faire. La sortie brute reste
toujours visible en dessous, pour qui veut le détail.

Deux usages :
  - expliquer(sortie)              : quand un outil lancé a échoué ;
  - expliquer_installation(raison) : quand l'installation d'un outil a raté
                                     (raison notée dans ~/vigie-installation.json).
"""
import re

# (motif, explication). L'ordre compte : du plus précis au plus général.
MOTIFS = [
    # --- Outils précis (avant les motifs généraux) ----------------------------
    (r"missing DNSPython",
     "dnstwist a été installé sans son module DNS (dnspython). Relancer l'installeur de "
     "Vigie : il l'ajoute tout seul. En attendant, Vigie le fait passer par le DNS de la "
     "machine, plus lent."),
    (r"undefined method [`']exists\?'",
     "Cette version de l'outil est trop ancienne pour le Ruby installé sur la machine "
     "(Ruby 3.2 et plus). Il faut une version plus récente de l'outil."),
    # --- Réseau -----------------------------------------------------------
    (r"temporary failure in name resolution|could not resolve host|name or service not "
     r"known|nodename nor servname|getaddrinfo failed|no such host|NXDOMAIN|"
     r"failed to resolve|name resolution",
     "L'ordinateur n'arrive pas à traduire les noms de sites en adresses (problème de "
     "DNS). Soit Internet est coupé, soit le serveur DNS de la machine ne répond pas. "
     "Vérifie qu'un site s'ouvre dans le navigateur."),
    (r"network is unreachable|no route to host",
     "L'ordinateur n'a pas d'accès à Internet en ce moment (réseau injoignable)."),
    (r"connection refused|ECONNREFUSED",
     "Le site ou le service visé a refusé la connexion : il est éteint, ou il n'écoute "
     "pas à cet endroit."),
    (r"timed? ?out|ETIMEDOUT|deadline exceeded",
     "La cible a mis trop de temps à répondre. Elle est peut-être lente, protégée, ou "
     "Internet est lent. On peut réessayer plus tard."),
    (r"certificate verify failed|SSL: CERTIFICATE|x509|self[- ]signed certificate",
     "Le certificat de sécurité (le cadenas HTTPS) n'a pas pu être vérifié : il est "
     "expiré, mal posé, ou un appareil du réseau intercepte la connexion."),
    (r"\b429\b|too many requests|rate[- ]?limit",
     "Le site interrogé a dit « trop de demandes » : il limite le nombre de questions. "
     "Il faut attendre un peu avant de relancer."),
    (r"\b(401|403)\b|unauthori[sz]ed|forbidden|access denied",
     "Accès refusé par le site ou le service interrogé : il faut un compte, une clé, ou "
     "il bloque les robots."),
    (r"api[ _-]?key|apikey|api token|no token|missing (?:key|token)|credentials? "
     r"(?:not found|missing|required)",
     "L'outil demande une clé d'accès (clé API) à un service en ligne, qui n'est pas "
     "réglée. Sans elle, cette partie de l'outil ne marche pas."),
    # --- Droits, fichiers ---------------------------------------------------
    (r"must be run as root|requires root|run as root|operation not permitted|"
     r"you don't have permission|are you root",
     "L'outil demande les droits administrateur (root). Vigie ne les lui donne pas "
     "automatiquement, par sécurité."),
    (r"permission denied",
     "Permission refusée : l'outil n'a pas le droit de lire ou d'écrire à cet endroit."),
    (r"no such file or directory|file not found|cannot open|does not exist",
     "L'outil cherche un fichier ou un dossier qui n'existe pas (sa configuration, ses "
     "règles, ou le fichier donné)."),
    (r"no space left on device",
     "Le disque est plein : il faut faire de la place avant de relancer."),
    (r"\bkilled\b|out of memory|MemoryError|cannot allocate memory",
     "L'ordinateur a manqué de mémoire vive et l'outil a été arrêté."),
    # --- Outil mal installé ------------------------------------------------
    (r"ModuleNotFoundError|No module named|ImportError",
     "L'outil est installé, mais il lui manque un morceau Python dont il a besoin. "
     "Il faut le réinstaller (relancer l'installeur de Vigie)."),
    (r"command not found|not found in \$?PATH|executable file not found",
     "L'outil essaie d'utiliser un autre programme qui n'est pas installé sur "
     "l'ordinateur."),
    (r"chrome|chromium|puppeteer|browser.*(not found|launch)",
     "L'outil a besoin du navigateur Google Chrome (ou Chromium) pour fonctionner, et "
     "ne l'a pas trouvé."),
    # --- Mauvaise utilisation ------------------------------------------------
    (r"archivebox init|not a valid archivebox|no archivebox|archivebox.*(index|collection)",
     "ArchiveBox a besoin d'un dossier d'archives préparé avant tout (commande "
     "« archivebox init » dans un dossier vide). Et il archive des pages web : il "
     "attend une adresse de site complète, pas un pseudo."),
    (r"unrecognized arguments?|unknown (?:flag|option|command|shorthand)|invalid "
     r"(?:option|argument|choice)|no such option|error: argument|usage:",
     "L'outil n'a pas compris la façon dont il a été appelé (la ligne de lancement ne "
     "lui convient pas). Ce n'est pas ta cible qui est en cause : la ligne devinée par "
     "Vigie est à corriger."),
    (r"Traceback \(most recent call last\)",
     "L'outil a planté pendant son travail (erreur interne du programme)."),
]

# Messages propres à l'INSTALLATION (rapport ~/vigie-installation.json).
MOTIFS_INSTALL = [
    (r"could not get lock|dpkg.*lock|unable to acquire the dpkg|lock-frontend",
     "Ubuntu était déjà en train d'installer ou de mettre à jour autre chose (mise à jour "
     "automatique) : l'installation a dû attendre son tour et a abandonné. Il suffit de "
     "relancer l'installeur un peu plus tard."),
    (r"\bbrew absent|brew: (?:command )?not found",
     "Homebrew (« brew ») est l'outil d'installation du Mac : il n'existe pas sur Ubuntu. "
     "C'est normal, ce n'est pas un vrai échec : sous Linux, Vigie passe par d'autres "
     "méthodes."),
    (r"\bpipx absent|pipx: (?:command )?not found",
     "pipx (qui installe les outils écrits en Python) n'est pas installé sur la machine."),
    (r"\bgo absent|go: (?:command )?not found",
     "Go (qui installe les outils écrits en langage Go) n'est pas installé sur la machine."),
    (r"\bnpm absent|npm: (?:command )?not found",
     "npm (qui installe les outils écrits en JavaScript) n'est pas installé sur la "
     "machine."),
    (r"\bsudo absent|a terminal is required|a password is required|sudo:.*password",
     "L'installation par apt demande le mot de passe administrateur, qui n'a pas pu être "
     "donné."),
    (r"npm ERR!|npm error|ERESOLVE|EACCES",
     "npm (l'installeur des outils JavaScript) a échoué : version de Node trop ancienne, "
     "droits insuffisants ou paquet cassé."),
    (r"neither 'setup\.py' nor 'pyproject\.toml'|does not appear to be a python project|"
     r"not a valid editable requirement|no matching distribution|could not find a version",
     "Vigie a essayé d'installer l'outil comme un programme Python, mais ce n'en est pas "
     "un (ou pas sous cette forme). Cet outil s'installe autrement : voir sa "
     "documentation."),
    (r"no go files|go\.mod file not found|cannot find main module|is not a main package|"
     r"module .* found, but does not contain package|invalid version|unknown revision",
     "Vigie a essayé d'installer l'outil comme un programme Go, mais ce n'en est pas un "
     "(ou pas sous cette forme). Cet outil s'installe autrement : voir sa documentation."),
    (r"unable to locate package|has no installation candidate|E: Package",
     "Ce paquet n'existe pas dans les dépôts d'Ubuntu (il existe parfois seulement sur "
     "Kali Linux)."),
    (r"externally-managed-environment",
     "Ubuntu interdit d'installer des outils Python « en vrac » dans le système : il "
     "faut passer par pipx."),
    (r"à installer à la main",
     "Cet outil ne s'installe pas tout seul (serveur, outil Windows, paquet Kali, "
     "Kubernetes…). Ce n'est pas une panne : la raison exacte est écrite juste à côté."),
    (r"bibliothèque Python|No apps associated",
     "Ce paquet Python est une bibliothèque (une brique pour d'autres programmes) : il "
     "n'apporte aucune commande à lancer."),
    (r"Cannot determine package name|Check package spec",
     "L'outil est un simple script Python, pas un paquet installable par pipx : il faut "
     "le copier depuis son dépôt et le lancer depuis son dossier."),
    (r"pkg_resources",
     "Il manque au programme un module ancien (setuptools) que les versions récentes de "
     "Python ne fournissent plus d'office."),
    (r"Python 3\.12",
     "Vigie a dû utiliser un Python 3.12 à part (celui de la machine est trop récent pour "
     "cet outil). C'est normal et sans risque pour le système."),
    (r"pas de dépôt|pas de méthode",
     "Vigie ne connaît aucune méthode d'installation automatique et sûre pour cet outil "
     "(pas de commande dans sa documentation). Il s'installe à la main."),
    (r"ne démarre pas",
     "L'installation a réussi, mais le programme ne démarre pas (il lui manque sans "
     "doute quelque chose)."),
    (r"dépassement",
     "L'installation a pris trop de temps et a été arrêtée (connexion lente ou outil "
     "très gros)."),
]


def _chercher(texte, motifs, maximum):
    trouve = []
    for motif, explication in motifs:
        if re.search(motif, texte or "", re.I) and explication not in trouve:
            trouve.append(explication)
            if len(trouve) >= maximum:
                break
    return trouve


def expliquer(sortie, maximum=3):
    """Les explications en français des erreurs reconnues dans la sortie (peut être vide)."""
    return _chercher(sortie, MOTIFS, maximum)


def expliquer_installation(raison, maximum=4):
    """Les explications en français d'un échec d'installation (rapport d'installation)."""
    trouve = _chercher(raison, MOTIFS_INSTALL, maximum)
    if len(trouve) < maximum:
        for texte in _chercher(raison, MOTIFS, maximum - len(trouve)):
            if texte not in trouve:
                trouve.append(texte)
    return trouve
