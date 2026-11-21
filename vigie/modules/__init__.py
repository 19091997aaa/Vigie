"""Le registre des modules de Vigie.

Pour ajouter un contrôle : écrire un fichier dans ce dossier avec une fonction
analyser(cible) qui renvoie (constats, données brutes), puis l'inscrire ici.
Si le contrôle ne peut pas se faire, la fonction lève ControleImpossible.

"actif"   = le module touche aux machines du client (scan de ports, recherche
            de failles). Jamais lancé sans autorisation signée.
"defaut"  = lancé quand on ne précise pas la liste des modules.
"""
from . import (accessibilite, adresses, apercu, liens, archives, checkdmarc_mod, chiffrement, conformite, domaines,
               mail, metadonnees, pseudos, qualite_site, site, sousdomaines, technos)

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
    "liens": {"fonction": liens.analyser, "bloc": "Exposition", "actif": False,
              "defaut": True, "nom": "Liens cassés du site (LinkChecker)"},
    "accessibilite": {"fonction": accessibilite.analyser, "bloc": "Exposition", "actif": False,
                      "defaut": True, "nom": "Accessibilité de la page d'accueil (Pa11y)"},
    "apercu": {"fonction": apercu.analyser, "bloc": "Exposition", "actif": False,
               "defaut": True, "nom": "Capture de la page d'accueil (gowitness)"},
    "pseudos": {"fonction": pseudos.analyser, "bloc": "Exposition", "actif": False,
                "defaut": False, "nom": "Comptes publics du dirigeant (Sherlock)"},
    "conformite": {"fonction": conformite.analyser, "bloc": "Conformité assureur",
                   "actif": False, "defaut": False, "nom": "Conformité assureur (questionnaire)"},
}

PAR_DEFAUT = [nom for nom, module in MODULES.items() if module["defaut"]]
