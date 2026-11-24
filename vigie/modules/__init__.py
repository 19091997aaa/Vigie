"""Le registre des modules de Vigie.

Pour ajouter un contrôle : écrire un fichier dans ce dossier avec une fonction
analyser(cible) qui renvoie (constats, données brutes), puis l'inscrire ici.
Si le contrôle ne peut pas se faire, la fonction lève ControleImpossible.

"actif"   = le module touche aux machines du client (scan de ports, recherche
            de failles). Jamais lancé sans autorisation signée.
"defaut"  = lancé quand on ne précise pas la liste des modules (diagnostic rapide).

Pour le diagnostic COMPLET (les 42 outils de la famille « diag gratuit », voir
vigie/diag_gratuit.py), trois réglages de plus, lus par cli.lancer :
"delai"   = secondes avant d'abandonner le contrôle (10 minutes si absent) ;
"chrome"  = il ouvre un navigateur : au plus 2 à la fois, sinon la machine sature ;
"apres"   = contrôles à attendre, parce qu'il relit ce qu'ils ont trouvé.
"""
from . import (accessibilite, adresses, apercu, archives, bibliotheques, complements, checkdmarc_mod, chiffrement, complet,
               comptes_mail, conformite, domaines, liens, mail, metadonnees, pseudos,
               qualite_site, site, sousdomaines, technos, telephone)

# L'ordre compte : quand deux outils relèvent le même problème (même clé), le rapport
# garde le texte du premier. Les contrôles écrits par Vigie passent donc en tête.
MODULES = {
    "mail": {"fonction": mail.analyser, "bloc": "Exposition", "actif": False, "defaut": True,
             "nom": "Réglages mail (usurpation)"},
    # Par défaut depuis le 21/11/2026 : 3 secondes, et il voit MTA-STS, TLS-RPT, DNSSEC.
    "checkdmarc": {"fonction": checkdmarc_mod.analyser, "bloc": "Exposition", "actif": False,
                   "defaut": True, "nom": "Réglages mail, 2e source (checkdmarc)"},
    "site": {"fonction": site.analyser, "bloc": "Exposition", "actif": False, "defaut": True,
             "nom": "Site internet (chiffrement, protections)"},
    # Les quatre suivants lisent ce que le site publie à un visiteur : pas « actifs ».
    "chiffrement": {"fonction": chiffrement.analyser, "bloc": "Exposition", "actif": False,
                    "defaut": True, "nom": "Versions du chiffrement (SSLyze)"},
    "qualite_site": {"fonction": qualite_site.analyser, "bloc": "Exposition", "actif": False,
                     "defaut": True, "nom": "Page d'accueil vue par Chrome (Lighthouse)"},
    "technos": {"fonction": technos.analyser, "bloc": "Exposition", "actif": False,
                "defaut": True, "nom": "Logiciels visibles du site (httpx)"},
    "sousdomaines": {"fonction": sousdomaines.analyser, "bloc": "Exposition", "actif": False,
                     "defaut": True, "nom": "Adresses annexes de la société (Subfinder)"},
    "domaines": {"fonction": domaines.analyser, "bloc": "Exposition", "actif": False,
                 "defaut": True, "nom": "Domaines imitateurs (dnstwist)"},
    "archives": {"fonction": archives.analyser, "bloc": "Exposition", "actif": False,
                 "defaut": True, "nom": "Anciennes pages dans les archives (gau)"},
    "metadonnees": {"fonction": metadonnees.analyser, "bloc": "Exposition", "actif": False,
                    "defaut": True, "nom": "Informations cachées des fichiers publiés (ExifTool)"},
    "adresses": {"fonction": adresses.analyser, "bloc": "Exposition", "actif": False,
                 "defaut": True, "nom": "Adresses mail visibles publiquement (theHarvester)"},
    "dns_complet": {"fonction": complements.analyser_dns, "bloc": "Exposition", "actif": False,
                    "defaut": True, "nom": "Fiche DNS complète (dnsrecon)"},
    "toutes_pages": {"fonction": complements.analyser_pages, "bloc": "Exposition",
                     "actif": False, "defaut": False,
                     "nom": "Toutes les pages vues par Chrome (Unlighthouse, ~1 min 30)"},
    "bibliotheques": {"fonction": bibliotheques.analyser, "bloc": "Exposition", "actif": False,
                      "defaut": True, "nom": "Bibliothèques JavaScript du site (Retire.js)"},
    "liens": {"fonction": liens.analyser, "bloc": "Exposition", "actif": False,
              "defaut": True, "nom": "Liens cassés du site (LinkChecker)"},
    "accessibilite": {"fonction": accessibilite.analyser, "bloc": "Exposition", "actif": False,
                      "defaut": True, "nom": "Accessibilité de la page d'accueil (Pa11y)"},
    "telephones_publics": {"fonction": telephone.analyser_publics, "bloc": "Exposition",
                           "actif": False, "defaut": True,
                           "nom": "Numéros de portable publiés sur le site"},
    # Recherche sur une personne : pseudos, mail, téléphone DONNÉS par elle, avec accord.
    "comptes_mail": {"fonction": comptes_mail.analyser, "bloc": "Exposition", "actif": False,
                     "defaut": False, "nom": "Comptes liés au mail du dirigeant (Holehe)"},
    "telephone": {"fonction": telephone.analyser, "bloc": "Exposition", "actif": False,
                  "defaut": False, "nom": "Numéro du dirigeant (PhoneInfoga)"},
    "apercu": {"fonction": apercu.analyser, "bloc": "Exposition", "actif": False,
               "defaut": True, "nom": "Capture de la page d'accueil (gowitness)"},
    "pseudos": {"fonction": pseudos.analyser, "bloc": "Exposition", "actif": False,
                "defaut": False, "nom": "Comptes publics du dirigeant (Sherlock, Maigret, user-scanner)"},
    # --- Diagnostic complet (24/11/2026) : le reste de la famille « diag gratuit ». ---
    "sousdomaines_amass": {"fonction": complet.analyser_amass, "bloc": "Exposition",
                           "actif": False, "defaut": False, "apres": ["sousdomaines"],
                           "nom": "Adresses annexes, 2e avis (Amass, mode passif)"},
    "alias_dns": {"fonction": complet.analyser_dnsx, "bloc": "Exposition", "actif": False,
                  "defaut": False, "apres": ["sousdomaines", "sousdomaines_amass"],
                  "nom": "Adresses annexes qui répondent encore (dnsx)"},
    "technos_whatweb": {"fonction": complet.analyser_whatweb, "bloc": "Exposition",
                        "actif": False, "defaut": False,
                        "nom": "Logiciels visibles du site, 2e avis (WhatWeb)"},
    "vitesse": {"fonction": complet.analyser_sitespeed, "bloc": "Exposition", "actif": False,
                "defaut": False, "chrome": True,
                "nom": "Vitesse de la page d'accueil (sitespeed.io)"},
    "captures": {"fonction": complet.analyser_eyewitness, "bloc": "Exposition",
                 "actif": False, "defaut": False, "chrome": True,
                 "nom": "Capture de la page d'accueil, 2e avis (EyeWitness)"},
    "moteurs_exposition": {"fonction": complet.analyser_uncover, "bloc": "Exposition",
                           "actif": False, "defaut": False,
                           "nom": "Ce que Shodan et Censys ont déjà vu (uncover)"},
    "documents_publics": {"fonction": complet.analyser_metagoofil, "bloc": "Exposition",
                          "actif": False, "defaut": False,
                          "nom": "Documents de la société trouvés par Google (Metagoofil)"},
    "photos": {"fonction": complet.analyser_exiv2, "bloc": "Exposition", "actif": False,
               "defaut": False, "nom": "Position GPS des photos du site (Exiv2)"},
    "instagram": {"fonction": complet.analyser_instaloader, "bloc": "Exposition",
                  "actif": False, "defaut": False,
                  "nom": "Compte Instagram de la société (Instaloader)"},
    "pseudos_societe": {"fonction": complet.analyser_pseudos_societe, "bloc": "Exposition",
                        "actif": False, "defaut": False, "delai": 1000,
                        "nom": "Le nom de la société sur les réseaux (Sherlock, Maigret, "
                               "user-scanner, Social Analyzer)"},
    "numeros_publics": {"fonction": complet.analyser_phoneinfoga, "bloc": "Exposition",
                        "actif": False, "defaut": False,
                        "nom": "Numéros affichés sur le site (PhoneInfoga)"},
    "archive_page": {"fonction": complet.analyser_archivebox, "bloc": "Exposition",
                     "actif": False, "defaut": False, "chrome": True, "delai": 900,
                     "nom": "Copie datée de la page d'accueil (ArchiveBox)"},
    "google_dirigeant": {"fonction": complet.analyser_ghunt, "bloc": "Exposition",
                         "actif": False, "defaut": False,
                         "nom": "Compte Google du dirigeant, avec son accord (GHunt)"},
    "conformite": {"fonction": conformite.analyser, "bloc": "Conformité assureur",
                   "actif": False, "defaut": False, "nom": "Conformité assureur (questionnaire)"},
}

# Réglages de durée et de navigateur des contrôles déjà existants.
for _nom, _reglage in {"toutes_pages": {"chrome": True, "delai": 900},
                       "qualite_site": {"chrome": True}, "accessibilite": {"chrome": True},
                       "apercu": {"chrome": True}, "pseudos": {"delai": 1200},
                       "liens": {"delai": 420},
                       "domaines": {"delai": 900}}.items():
    MODULES[_nom].update(_reglage)

PAR_DEFAUT = [nom for nom, module in MODULES.items() if module["defaut"]]

# Le diagnostic complet : tout ce qui n'est pas actif, sauf le questionnaire assureur
# (il demande des réponses du client). Les contrôles sur la personne du dirigeant
# (pseudos, holehe, téléphone, GHunt) y figurent : sans son accord écrit, ils disent
# simplement pourquoi ils ne tournent pas.
COMPLET = [nom for nom, module in MODULES.items()
           if not module["actif"] and nom != "conformite"]
