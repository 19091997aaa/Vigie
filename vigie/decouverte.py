"""Deviner la ligne de lancement d'un outil en lisant sa propre aide.

Déclarer 222 outils à la main est impossible, et les écrire de mémoire serait
inventer. Mais chaque outil sait décrire sa syntaxe : « --help ». On la lit, on
en tire une proposition de déclaration, et on annonce une confiance.

Rien n'est accepté sans vérification : la proposition se vérifie en la lançant.
"""
import re
import shutil
import subprocess

DEMANDES_AIDE = [["--help"], ["-h"], ["help"], []]

# Drapeaux par lesquels un outil reçoit sa cible, du plus explicite au plus vague.
DRAPEAUX_CIBLE = [
    (re.compile(r"(?<![\w-])(--domain)\b", re.I), "--domain", 5),
    (re.compile(r"(?<![\w-])(-d)\b(?![\w-])"), "-d", 4),
    (re.compile(r"(?<![\w-])(--url)\b", re.I), "--url", 4),
    (re.compile(r"(?<![\w-])(--target)\b", re.I), "--target", 4),
    (re.compile(r"(?<![\w-])(--host)\b", re.I), "--host", 3),
    (re.compile(r"(?<![\w-])(-u)\b(?![\w-])"), "-u", 2),
    (re.compile(r"(?<![\w-])(-t)\b(?![\w-])"), "-t", 2),
]

# Drapeaux qui réduisent le bruit : une sortie propre se mesure bien mieux.
DRAPEAUX_SILENCE = [
    (re.compile(r"(?<![\w-])(-silent)\b", re.I), "-silent"),
    (re.compile(r"(?<![\w-])(--silent)\b", re.I), "--silent"),
    (re.compile(r"(?<![\w-])(--quiet)\b", re.I), "--quiet"),
    (re.compile(r"(?<![\w-])(--no-color)\b", re.I), "--no-color"),
]

# « usage: outil [OPTION]... DOMAIN » : la cible se passe sans drapeau.
# Vérifié sur dnstwist, dont l'usage est positionnel alors qu'il a aussi un « -d ».
POSITIONNEL = re.compile(
    r"usage:.*?[\s<\[]*(domain|target|url|host)(?:name)?s?[>\].]*\s*$",
    re.I | re.M)

# Un drapeau suivi d'un type d'argument n'est PAS la cible : « -d, --dictionary FILE »
# chez dnstwist attend un fichier. Le confondre avec le domaine produit une commande fausse.
ARGUMENT_NOMME = re.compile(
    r"\b(FILE|FILENAME|PATH|LIST|DIR|DICT\w*|WORDLIST|NUM|SECONDS|FORMAT)\b")

# Un drapeau décrit sur la même ligne que l'un de ces mots n'est pas la cible non plus :
# chez sherlock, « --verbose, -v, -d, --debug » fait de -d un synonyme de --debug.
NON_CIBLE = re.compile(
    r"\b(debug|verbose|version|help|delay|depth|directory|dictionar\w+|database|"
    r"output|outfile|wordlist|thread\w*|timeout|proxy|dump)\b", re.I)

# Le bloc « usage » peut tenir sur plusieurs lignes : la cible y apparaît en capitales.
CIBLE_DANS_USAGE = re.compile(r"\b(DOMAIN|DOMAINS|TARGET|TARGETS|URL|URLS|HOST|HOSTS|"
                              r"USERNAME|USERNAMES)\b")


def _bloc_usage(texte):
    """Le bloc « usage: ... » jusqu'à la première ligne vide, car il peut se replier.

    On retire les groupes entre crochets : « [-d DOMAIN] » décrit une option et son
    argument, pas une cible positionnelle. Ce qui reste après est la vraie cible.
    Vérifié : dnsrecon a « [-d DOMAIN] » (drapeau), sherlock finit par « USERNAMES »
    et dnstwist par « DOMAIN » (positionnels).
    """
    debut = texte.lower().find("usage")
    if debut < 0:
        return ""
    fin = texte.find("\n\n", debut)
    bloc = texte[debut:fin if fin > 0 else min(len(texte), debut + 600)]
    return re.sub(r"\[[^\[\]]*\]", " ", bloc)


def aide(commande, delai=20):
    """Le texte d'aide de l'outil, en essayant plusieurs façons de le demander."""
    chemin = shutil.which(commande)
    if not chemin:
        return ""
    meilleur = ""
    for arguments in DEMANDES_AIDE:
        try:
            fini = subprocess.run([chemin] + arguments, capture_output=True, text=True,
                                  timeout=delai, errors="replace")
        except (subprocess.TimeoutExpired, OSError):
            continue
        texte = (fini.stdout or "") + "\n" + (fini.stderr or "")
        if len(texte.strip()) > len(meilleur.strip()):
            meilleur = texte
        if "usage" in texte.lower() and len(texte) > 200:
            break
    return meilleur


def proposer(commande, texte_aide=None):
    """Propose une déclaration de lancement à partir de l'aide. Annonce sa confiance."""
    texte = texte_aide if texte_aide is not None else aide(commande)
    if not texte.strip():
        return {"commande": commande, "arguments": [], "confiance": "nulle",
                "indices": "aucune aide lisible"}
    indices, arguments = [], []
    for motif, drapeau in DRAPEAUX_SILENCE:
        if motif.search(texte):
            arguments.append(drapeau)
            indices.append(f"silence : {drapeau}")
            break
    # L'« usage » de l'outil fait foi : il décrit la vraie façon de l'appeler.
    usage = _bloc_usage(texte)
    if POSITIONNEL.search(texte) or CIBLE_DANS_USAGE.search(usage):
        arguments.append("{cible}")
        indices.append("cible : sans drapeau (lue dans « usage »)")
        return {"commande": commande, "arguments": arguments,
                "confiance": "bonne", "indices": " | ".join(indices)}
    meilleur_drapeau, meilleur_poids = None, 0
    for motif, drapeau, poids in DRAPEAUX_CIBLE:
        trouve = motif.search(texte)
        if not trouve or poids <= meilleur_poids:
            continue
        # On juge le drapeau sur la ligne entière qui le décrit.
        debut_ligne = texte.rfind("\n", 0, trouve.start()) + 1
        fin = texte.find("\n", trouve.end())
        ligne = texte[debut_ligne:fin if fin > 0 else len(texte)]
        if NON_CIBLE.search(ligne):
            indices.append(f"{drapeau} écarté (synonyme d'une option qui n'est pas la cible)")
            continue
        if ARGUMENT_NOMME.search(ligne[trouve.start() - debut_ligne:][:60]):
            indices.append(f"{drapeau} écarté (attend un fichier, pas un domaine)")
            continue
        meilleur_drapeau, meilleur_poids = drapeau, poids
    if meilleur_drapeau:
        arguments += [meilleur_drapeau, "{cible}"]
        indices.append(f"cible : {meilleur_drapeau}")
        confiance = "bonne" if meilleur_poids >= 4 else "moyenne"
    else:
        arguments.append("{cible}")
        indices.append("cible : supposée sans drapeau, aucun indice trouvé")
        confiance = "faible"
    return {"commande": commande, "arguments": arguments,
            "confiance": confiance, "indices" : " | ".join(indices)}


def en_texte(propositions):
    lignes = ["DÉCOUVERTE DES LIGNES DE LANCEMENT", ""]
    ordre = {"bonne": 0, "moyenne": 1, "faible": 2, "nulle": 3}
    for proposition in sorted(propositions, key=lambda p: ordre.get(p["confiance"], 9)):
        ligne = " ".join([proposition["commande"]] + proposition["arguments"])
        lignes.append(f"  [{proposition['confiance']:>7}]  {ligne}")
        lignes.append(f"             {proposition['indices']}")
    lignes += ["", "À vérifier en lançant : les propositions « faible » sont des suppositions."]
    return "\n".join(lignes)
