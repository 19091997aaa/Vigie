"""Le registre des modules de Vigie.

Pour ajouter un contrôle : écrire un fichier dans ce dossier avec une fonction
analyser(cible) qui renvoie (constats, données brutes), puis l'inscrire ici.
Si le contrôle ne peut pas se faire, la fonction lève ControleImpossible.

"actif"   = le module touche aux machines du client (scan de ports, recherche
            de failles). Jamais lancé sans autorisation signée.
"defaut"  = lancé quand on ne précise pas la liste des modules.
"""
from . import checkdmarc_mod, conformite, domaines, mail, pseudos, site

MODULES = {
    "mail": {"fonction": mail.analyser, "bloc": "Exposition", "actif": False, "defaut": True,
             "nom": "Réglages mail (usurpation)"},
    "checkdmarc": {"fonction": checkdmarc_mod.analyser, "bloc": "Exposition", "actif": False,
                   "defaut": False, "nom": "Réglages mail, 2e source (checkdmarc)"},
    "site": {"fonction": site.analyser, "bloc": "Exposition", "actif": False, "defaut": True,
             "nom": "Site internet (chiffrement, protections)"},
    "domaines": {"fonction": domaines.analyser, "bloc": "Exposition", "actif": False,
                 "defaut": True, "nom": "Domaines imitateurs (dnstwist)"},
    "pseudos": {"fonction": pseudos.analyser, "bloc": "Exposition", "actif": False,
                "defaut": False, "nom": "Comptes publics du dirigeant (Sherlock)"},
    "conformite": {"fonction": conformite.analyser, "bloc": "Conformité assureur",
                   "actif": False, "defaut": False, "nom": "Conformité assureur (questionnaire)"},
}

PAR_DEFAUT = [nom for nom, module in MODULES.items() if module["defaut"]]
