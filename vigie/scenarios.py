"""« Ce qu'un escroc pourrait faire » : traduit les constats en conséquences concrètes,
en français de patron. C'est l'arme de vente du diagnostic gratuit.

Règle d'honnêteté : un scénario n'apparaît QUE si les constats qui le rendent possible
sont réellement présents. Pas de peur inventée — chaque scénario est adossé à un vrai
défaut trouvé. On décrit un risque réel ; on n'affirme jamais qu'une attaque est en cours.
"""
from .modeles import CRITIQUE, IMPORTANT, INFO, ORDRE


def _presence(constats, cle, niveau_min=INFO):
    """Un constat de cette clé existe-t-il, au moins aussi grave que niveau_min ?"""
    seuil = ORDRE[niveau_min]
    return any(c["cle"] == cle and ORDRE[c["niveau"]] <= seuil for c in constats)


# Chaque scénario : son déclencheur (quels constats le rendent possible) et son récit.
REGLES = [
    {
        "id": "faux_fournisseur",
        "titre": "Une fausse facture envoyée à vos clients en votre nom",
        "gravite": CRITIQUE,
        "declenche": lambda cs: _presence(cs, "dmarc", IMPORTANT)
                     or _presence(cs, "spf", IMPORTANT)
                     or _presence(cs, "domaines_imitateurs", IMPORTANT),
        "texte": ("Un escroc peut envoyer un mail qui affiche votre adresse (ou une adresse "
                  "qui vous imite) et y glisser une facture avec SON compte bancaire à la "
                  "place du vôtre. Vos clients paient l'escroc en croyant vous régler. "
                  "C'est la fraude au faux fournisseur, la plus coûteuse pour les petites "
                  "entreprises — l'argent part et ne revient pas."),
    },
    {
        "id": "hameconnage_salaries",
        "titre": "Vos salariés piégés par un site qui imite le vôtre",
        "gravite": IMPORTANT,
        "declenche": lambda cs: _presence(cs, "domaines_imitateurs", INFO),
        "texte": ("Un domaine qui ressemble au vôtre, à une lettre près, peut servir à piéger "
                  "vos salariés ou vos clients : faux mail, fausse page de connexion, faux "
                  "espace de paiement. Ils croient être chez vous et donnent leurs identifiants "
                  "ou leur carte."),
    },
    {
        "id": "interception_echanges",
        "titre": "Ce que tapent vos visiteurs peut être lu",
        "gravite": IMPORTANT,
        "declenche": lambda cs: _presence(cs, "chiffrement", IMPORTANT),
        "texte": ("Sans connexion correctement chiffrée, ce que vos visiteurs saisissent sur "
                  "votre site (formulaire, identifiants) peut être lu ou modifié sur un réseau "
                  "public — une borne Wi-Fi d'hôtel ou de gare, par exemple."),
    },
]


def scenarios_pour(constats_en_dict):
    """Renvoie les scénarios réellement possibles, du plus grave au moins grave.
    `constats_en_dict` est la liste des constats sous forme de dictionnaires (comme dans
    le rapport)."""
    trouves = [
        {"titre": regle["titre"], "gravite": regle["gravite"], "texte": regle["texte"]}
        for regle in REGLES if regle["declenche"](constats_en_dict)
    ]
    return sorted(trouves, key=lambda s: ORDRE[s["gravite"]])
