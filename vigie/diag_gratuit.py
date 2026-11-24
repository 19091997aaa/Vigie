"""Les 42 outils de la famille « diagnostic gratuit » : lequel tourne, lequel non, pourquoi.

Demande d'Anass (24/11/2026) : que les 42 outils du diagnostic gratuit soient
utilisés, quitte à ce que le contrôle soit plus long, pour apprendre à les faire
marcher ensemble. Aucun outil n'est passé sous silence : chacun a une ligne dans le
rapport, avec ce qui s'est passé en français.

Pour chaque outil :
  - "module"   : le contrôle de Vigie qui le lance (voir vigie/modules) ;
  - "commande" : sa clé dans outils.CATALOGUE, pour savoir s'il est installé ;
  - "raison"   : s'il ne PEUT PAS tourner dans un diagnostic automatique, pourquoi,
                 et ce qu'il lui faudrait. Ces outils-là ne sont jamais lancés ;
  - "ecarte"   : il enfreindrait les règles d'or du diagnostic gratuit (fuites, dark web).
"""
from . import outils, registre

# Les outils qu'aucune entrée tirée du domaine ne peut faire tourner seuls.
SERVICE_DNS = ("c'est un serveur DNS filtrant à installer sur le réseau du client (il "
               "bloque les sites dangereux pour tous ses appareils). Il ne s'utilise pas sur "
               "un domaine : il a sa place dans l'offre sécurisation, pas dans le diagnostic")

OUTILS = {
    # --- Lancés dans le diagnostic -----------------------------------------
    "checkdmarc": {"module": "checkdmarc", "commande": "checkdmarc"},
    "SSLyze": {"module": "chiffrement", "commande": "sslyze"},
    "Lighthouse": {"module": "qualite_site", "commande": "lighthouse"},
    "httpx": {"module": "technos", "commande": "httpx"},
    "Subfinder": {"module": "sousdomaines", "commande": "subfinder"},
    "dnstwist": {"module": "domaines", "commande": "dnstwist"},
    "gau": {"module": "archives", "commande": "gau"},
    "ExifTool": {"module": "metadonnees", "commande": "exiftool"},
    "theHarvester": {"module": "adresses", "commande": "theHarvester"},
    "dnsrecon": {"module": "dns_complet", "commande": "dnsrecon"},
    "Unlighthouse": {"module": "toutes_pages", "commande": "unlighthouse"},
    "LinkChecker": {"module": "liens", "commande": "linkchecker"},
    "Pa11y": {"module": "accessibilite", "commande": "pa11y"},
    "gowitness": {"module": "apercu", "commande": "gowitness"},
    "OWASP Amass": {"module": "sousdomaines_amass", "commande": "amass"},
    "dnsx": {"module": "alias_dns", "commande": "dnsx"},
    "WhatWeb": {"module": "technos_whatweb", "commande": "whatweb"},
    "sitespeed.io": {"module": "vitesse", "commande": "sitespeed.io"},
    "EyeWitness": {"module": "captures", "commande": "eyewitness"},
    "uncover": {"module": "moteurs_exposition", "commande": "uncover"},
    "Metagoofil": {"module": "documents_publics", "commande": "metagoofil"},
    "Exiv2": {"module": "photos", "commande": "exiv2"},
    "Instaloader": {"module": "instagram", "commande": "instaloader"},
    "Sherlock": {"module": "pseudos_societe", "commande": "sherlock"},
    "Maigret": {"module": "pseudos_societe", "commande": "maigret"},
    "user-scanner": {"module": "pseudos_societe", "commande": "user-scanner"},
    "Social Analyzer": {"module": "pseudos_societe", "commande": "social-analyzer"},
    "PhoneInfoga": {"module": "numeros_publics", "commande": "phoneinfoga"},
    "ArchiveBox": {"module": "archive_page", "commande": "archivebox"},
    # --- Seulement avec l'accord écrit du dirigeant (données personnelles) ---
    "Holehe": {"module": "comptes_mail", "commande": "holehe"},
    "GHunt": {"module": "google_dirigeant", "commande": "ghunt"},
    # --- Jamais lancés automatiquement : la raison s'affiche dans le rapport ---
    "AdGuard Home": {"raison": SERVICE_DNS},
    "Pi-hole": {"raison": SERVICE_DNS},
    "Web-Check": {"raison": "c'est une application web à ouvrir dans le navigateur, pas une "
                            "commande. Elle contient aussi un scan de ports (actif), interdit "
                            "dans le diagnostic gratuit. Ses contrôles passifs sont déjà faits "
                            "par les autres outils"},
    "Datashare": {"raison": "c'est un logiciel de bureau pour ranger et fouiller SES PROPRES "
                            "documents : il n'interroge rien sur internet"},
    "Flowsint": {"raison": "c'est une plateforme d'enquête à ouvrir dans le navigateur (schéma "
                           "« qui est relié à quoi »), à remplir à la main"},
    "InVID-WeVerify": {"raison": "c'est une extension du navigateur pour vérifier si une photo "
                                 "ou une vidéo est truquée : elle s'utilise à la main"},
    "geo-sleuth": {"raison": "c'est une compétence pour assistant IA (deviner où une photo a "
                             "été prise), pas un programme qu'on lance"},
    "IVRE": {"raison": "c'est une plateforme complète (base de données + interface) qui se "
                       "nourrit de scans de ports : ces scans sont actifs, donc réservés à "
                       "l'audit sur autorisation signée"},
    "auto-archiver": {"raison": "il faut d'abord écrire son fichier de configuration "
                                "(orchestration.yaml) ; ArchiveBox fait déjà la copie datée "
                                "du site dans le diagnostic"},
    "Toutatis": {"raison": "il exige d'être connecté à un compte Instagram (identifiant de "
                           "session) et sert à extraire l'e-mail et le téléphone d'une "
                           "PERSONNE : hors diagnostic gratuit"},
    "Robin": {"ecarte": True, "raison": "il fouille le dark web, où se revendent les "
                        "données volées. C'est interdit à froid (CNIL, recel art. 321-1) ; "
                        "réservé à l'offre payante, après accord et vérification du domaine. "
                        "Il demande aussi Tor et une clé d'IA payante"},
}

def noms_famille():
    """Les noms des outils classés « diagnostic gratuit » dans le catalogue (42)."""
    return sorted(o["nom"] for o in registre.charger() if o["famille"] == "diag")


def bilan(deroule, installe=None):
    """Une ligne par outil des 42 : {"outil", "etat", "texte", "duree"}.

    deroule : la liste rapport["deroule"] (un élément par contrôle lancé).
    installe : fonction nom_catalogue -> bool (par défaut : outils.disponible).
    """
    installe = installe or outils.disponible
    par_module = {e["module"]: e for e in deroule or []}
    lignes = []
    for outil in sorted(OUTILS, key=str.lower):
        fiche = OUTILS[outil]
        if "raison" in fiche:
            lignes.append({"outil": outil, "etat": "ecarte" if fiche.get("ecarte") else "jamais",
                           "texte": fiche["raison"], "duree": None})
            continue
        etape = par_module.get(fiche["module"])
        if etape is None:
            etat, texte, duree = "hors_liste", "pas dans la liste des contrôles demandés", None
        elif not installe(fiche["commande"]):
            etat, duree = "absent", None
            texte = "à installer : " + outils.astuce_installation(fiche["commande"])
        elif etape["etat"] == "fini":
            etat = "lance"
            texte, duree = f"{etape['nom']} : {etape['detail']}", etape["duree"]
        else:
            etat, texte, duree = etape["etat"], etape["detail"], etape["duree"]
        lignes.append({"outil": outil, "etat": etat, "texte": texte, "duree": duree})
    return lignes


def compte(lignes):
    """{"lance": 20, "absent": 5, …} pour le résumé."""
    total = {}
    for ligne in lignes:
        total[ligne["etat"]] = total.get(ligne["etat"], 0) + 1
    return total
