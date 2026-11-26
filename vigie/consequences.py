"""« Conséquences » : pour chaque type de constat, ce que ça peut coûter au dirigeant.

Quatre rubriques, en français de patron :
- attaquant  : ce qu'un escroc peut concrètement faire avec ce défaut ;
- entreprise : ce que ça coûte (argent, image, arrêt d'activité, données clients) ;
- loi        : ce que l'État peut reprocher (RGPD, CNIL, Code pénal, NIS2) ;
- assurance  : comment un assureur cyber peut réagir.

Règles d'honnêteté (demande d'Anass du 24/11/2026, cadre de MARCHE.md) :
- Toujours « peut », avec la condition. Jamais « vous allez ».
- Aucun montant d'amende inventé par constat. Les plafonds légaux sont donnés UNE fois,
  avec leur contexte, dans CADRE_GENERAL (affiché en fin de rapport).
- Une rubrique sans rapport réel avec le défaut reste vide (pas de loi pour une page lente).
- Chaque texte cité est listé dans docs/sources-consequences.md.

Un seul endroit : ce fichier. Une clé = la même clé que le constat (`Constat.cle`).
"""
import re

from .modeles import OK

# --- Morceaux réutilisés (textes vérifiés, voir docs/sources-consequences.md) --------

RGPD_SECURITE = ("Si des données personnelles (clients, salariés) sont touchées, la CNIL peut "
                 "reprocher un manque de sécurité : le RGPD (art. 32) oblige toute entreprise "
                 "à protéger les données qu'elle traite.")
RGPD_FUITE = ("En cas de fuite de données personnelles, vous devez prévenir la CNIL dans les "
              "72 heures (RGPD art. 33), et les personnes touchées si le risque est élevé "
              "(art. 34).")
ASSURANCE_HYGIENE = ("Les assureurs cyber demandent ces protections de base dans leur "
                     "questionnaire. Si elles manquent, ils peuvent augmenter la prime, "
                     "exclure ce risque ou refuser de vous couvrir.")
ASSURANCE_FRAUDE = ("La fraude au faux virement n'est pas toujours couverte : beaucoup de "
                    "contrats cyber l'excluent ou la plafonnent. Vérifiez votre contrat.")

# --- Les conséquences, par clé de constat -------------------------------------------

CONSEQUENCES = {
    # ---------------- Mail : usurpation de votre adresse ----------------
    "spf": {
        "attaquant": "Un escroc peut envoyer des mails qui semblent venir de votre adresse, "
                     "par exemple une fausse facture avec son propre RIB.",
        "entreprise": "Vos clients peuvent payer l'escroc en croyant vous payer. L'argent "
                      "est rarement récupéré, et la confiance de vos clients en prend un coup.",
        "loi": "Un client victime peut chercher à engager votre responsabilité civile s'il "
               "estime que votre négligence a facilité l'escroquerie (Code civil, art. 1240).",
        "assurance": ASSURANCE_FRAUDE,
    },
    "dmarc": {
        "attaquant": "Rien ne dit aux messageries de refuser un faux mail à votre nom. Un "
                     "escroc peut écrire à vos clients ou à votre comptable en se faisant "
                     "passer pour vous.",
        "entreprise": "Fausses factures, faux ordres de virement, demandes de mot de passe : "
                      "ce sont les arnaques les plus coûteuses pour les petites entreprises.",
        "loi": "Un client victime peut chercher à engager votre responsabilité civile s'il "
               "estime que votre négligence a facilité l'escroquerie (Code civil, art. 1240).",
        "assurance": ASSURANCE_FRAUDE,
    },
    "dkim": {
        "attaquant": "Vos vrais mails ne portent pas de signature : il est plus facile de "
                     "les imiter, et plus difficile de prouver qu'un faux n'est pas de vous.",
        "entreprise": "Certains de vos mails peuvent finir en indésirables chez vos clients.",
    },
    "mx": {
        "attaquant": "Un domaine qui ne reçoit pas de mail mais n'interdit pas l'envoi peut "
                     "servir à envoyer des faux mails à votre nom.",
    },
    "dmarc_rapports": {
        "attaquant": "Si quelqu'un envoie des faux mails à votre nom, vous ne le saurez pas.",
        "entreprise": "Vous découvrez l'arnaque quand un client vous appelle, trop tard.",
    },
    "dmarc_pct": {
        "entreprise": "Une règle mal écrite peut être mal comprise par les messageries : "
                      "votre protection contre les faux mails est moins fiable.",
    },
    "spf_ptr": {
        "entreprise": "Ce réglage peut faire échouer le contrôle chez certaines messageries : "
                      "vos mails risquent d'arriver en indésirables.",
    },
    "mta_sts": {
        "attaquant": "Les mails qu'on vous envoie peuvent, dans certains cas, être lus en "
                     "route si un attaquant se place sur le chemin.",
    },
    "tls_rpt": {
        "entreprise": "Si la livraison de vos mails est attaquée ou en panne, personne ne "
                      "vous prévient.",
    },
    "dnssec": {
        "attaquant": "Dans certains cas, un attaquant peut fausser l'adresse de votre site ou "
                     "de votre messagerie et rediriger vos visiteurs ailleurs.",
    },

    # ---------------- Site : connexion chiffrée ----------------
    "https": {
        "attaquant": "Sur un Wi-Fi public (hôtel, gare, café), quelqu'un peut lire ou "
                     "modifier ce que vos visiteurs tapent sur votre site : formulaire, "
                     "identifiants.",
        "entreprise": "Les navigateurs affichent « Non sécurisé » : des clients repartent, "
                      "et Google classe moins bien votre site.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "redirection_https": {
        "attaquant": "Un visiteur qui tape votre adresse arrive sur la version non chiffrée. "
                     "Sur un Wi-Fi public, ce qu'il saisit peut être lu ou modifié.",
        "entreprise": "Vos clients peuvent se faire voler leurs identifiants sans que vous "
                      "le sachiez.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "hsts": {
        "attaquant": "Sur le Wi-Fi d'un hôtel, d'une gare ou d'un client, un attaquant peut "
                     "faire basculer votre visiteur sur une version non chiffrée du site, "
                     "sans qu'il le voie, et lui voler ses identifiants.",
        "entreprise": "Un salarié ou un client qui se connecte en déplacement peut se faire "
                      "voler son compte. Ce compte peut ensuite servir à entrer chez vous.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "certificat": {
        "attaquant": "Un certificat invalide habitue vos visiteurs à cliquer sur « continuer "
                     "quand même » : un faux site à votre nom passerait inaperçu.",
        "entreprise": "Le navigateur affiche une alerte rouge : la plupart des visiteurs "
                      "partent. Si le certificat expire, le site devient inaccessible.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "certificat_www": {
        "attaquant": "Les visiteurs qui tapent « www » tombent sur une alerte de sécurité ; "
                     "certains l'ignorent et deviennent faciles à piéger.",
        "entreprise": "Une partie de vos visiteurs voit une page d'erreur au lieu de votre "
                      "site.",
    },
    "chiffrement": {   # anciens rapports (avant le 21/11/2026)
        "attaquant": "Sur un Wi-Fi public, ce que vos visiteurs tapent peut être lu.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "protocoles_anciens": {
        "attaquant": "Le site accepte de vieilles versions du chiffrement, avec des failles "
                     "connues. Un attaquant bien placé peut, dans certains cas, déchiffrer "
                     "les échanges.",
        "entreprise": "Ces vieilles versions sont refusées par les navigateurs récents et "
                      "signalées dans les audits de vos clients ou partenaires.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "chiffrements_faibles": {
        "attaquant": "Le chiffrement accepte des méthodes trop faibles : un attaquant "
                     "patient peut, dans certains cas, casser la protection.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "tls13": {
        "entreprise": "Pas de danger immédiat : le site n'utilise pas la version la plus "
                      "récente et la plus rapide du chiffrement.",
    },
    "contenu_mixte": {
        "attaquant": "Certains éléments de la page arrivent sans chiffrement : sur un Wi-Fi "
                     "public, un attaquant peut les remplacer, par exemple par un faux "
                     "formulaire.",
        "entreprise": "Le navigateur peut afficher « Non sécurisé » ou bloquer une partie "
                      "de la page.",
        "loi": RGPD_SECURITE,
    },

    # ---------------- Site : protections des pages ----------------
    "csp": {
        "attaquant": "Si une faille permet d'injecter du code dans votre site, rien ne "
                     "l'arrête : il peut voler ce que tapent vos visiteurs ou les "
                     "rediriger vers un faux site.",
        "entreprise": "Votre site peut servir à piéger vos propres clients.",
    },
    "nosniff": {
        "attaquant": "Un fichier piégé peut se faire passer pour un fichier inoffensif et "
                     "s'exécuter dans le navigateur du visiteur.",
    },
    "cadre": {
        "attaquant": "Un faux site peut afficher votre site en transparence et faire cliquer "
                     "vos visiteurs sur des boutons qu'ils ne voient pas.",
        "entreprise": "Un client peut valider une action sans le vouloir sur votre site.",
    },
    "coop": {
        "attaquant": "Une page piégée ouverte depuis votre site peut agir sur lui.",
    },
    "versions_visibles": {
        "attaquant": "Le site annonce les versions de ses logiciels. Un attaquant sait tout "
                     "de suite quelles failles connues essayer.",
        "entreprise": "Ça ne crée pas de faille, mais ça raccourcit le travail d'un pirate.",
    },
    "bibliotheques": {
        "attaquant": "Le site utilise des composants avec des failles publiques. Des robots "
                     "cherchent ces failles en permanence, sur tous les sites.",
        "entreprise": "Site piraté, défiguré ou utilisé pour piéger vos visiteurs ; remise en "
                      "état à payer.",
        "loi": RGPD_SECURITE,
        "assurance": "Les assureurs demandent des mises à jour régulières (souvent sous 30 "
                     "jours). Une faille connue non corrigée peut réduire votre "
                     "indemnisation.",
    },
    "cms": {
        "attaquant": "Les outils comme WordPress sont les plus visés : un module pas à jour "
                     "suffit pour entrer.",
        "entreprise": "Pas un défaut en soi. Le risque vient des mises à jour oubliées.",
    },
    "technos_whatweb": {
        "attaquant": "Connaître vos logiciels aide un attaquant à choisir ses failles.",
    },

    # ---------------- Adresses annexes et services exposés ----------------
    "alias_orphelins": {
        "attaquant": "Une adresse à votre nom pointe vers un service abandonné. Un escroc "
                     "peut le reprendre et publier ce qu'il veut sous votre nom de domaine : "
                     "faux site, fausse page de connexion.",
        "entreprise": "Un faux site sous votre propre adresse est très crédible : clients et "
                      "salariés n'ont aucun moyen de voir le piège.",
        "loi": RGPD_SECURITE,
    },
    "sous_domaines": {
        "attaquant": "Chaque adresse annexe est une porte de plus à essayer. Les vieilles "
                     "pages oubliées sont souvent les moins protégées.",
    },
    "sous_domaines_amass": {
        "attaquant": "Chaque adresse annexe est une porte de plus à essayer.",
    },
    "adresses_muettes": {
        "attaquant": "Des adresses à votre nom ne mènent plus nulle part. Si le service "
                     "derrière est libéré, quelqu'un peut le reprendre.",
    },
    "sites_annexes": {
        "attaquant": "D'autres sites de la société répondent. S'ils sont oubliés, ils ne "
                     "sont plus mis à jour et deviennent une porte d'entrée.",
    },
    "technos_non_chiffre": {
        "attaquant": "Ce site répond sans chiffrement : sur un Wi-Fi public, ce qu'on y tape "
                     "peut être lu.",
        "loi": RGPD_SECURITE,
        "assurance": ASSURANCE_HYGIENE,
    },
    "moteurs_exposition": {
        "attaquant": "Des moteurs publics ont déjà recensé vos services. Un attaquant n'a "
                     "pas besoin de vous scanner : la liste est en ligne.",
    },
    "dns_complet": {
        "attaquant": "Votre fiche DNS révèle vos prestataires (messagerie, outils). Un "
                     "escroc peut s'en servir pour un faux mail crédible « de la part de "
                     "Microsoft » ou de votre prestataire.",
    },
    "liens_domaines_morts": {
        "attaquant": "Des liens de votre site mènent à des domaines abandonnés. N'importe "
                     "qui peut les racheter et y mettre un faux site : vos visiteurs y "
                     "arrivent depuis chez vous, en confiance.",
        "entreprise": "Votre site peut, sans le vouloir, envoyer vos clients chez un escroc.",
    },
    "liens_casses": {
        "entreprise": "Des pages d'erreur sur votre site : image moins sérieuse, et Google "
                      "classe moins bien le site.",
    },

    # ---------------- Imitations ----------------
    "domaines_imitateurs": {
        "attaquant": "Des domaines qui ressemblent au vôtre existent. Ils peuvent servir à "
                     "envoyer des faux mails ou à afficher un faux site qui vous imite.",
        "entreprise": "Vos clients peuvent payer une fausse facture ou donner leurs "
                      "identifiants en croyant être chez vous.",
        "loi": "Vous pouvez faire supprimer ou récupérer un domaine qui vous imite : "
               "procédure Syreli de l'Afnic pour les .fr, procédure UDRP pour les .com.",
        "assurance": ASSURANCE_FRAUDE,
    },
    "marque": {
        "attaquant": "Votre nom est déjà pris sur d'autres sites. Quelqu'un peut ouvrir un "
                     "faux compte à votre nom et contacter vos clients.",
        "entreprise": "Un faux compte peut abîmer votre image ou servir à des arnaques.",
    },

    # ---------------- Informations publiées ----------------
    "archives_sensibles": {
        "attaquant": "Des fichiers sensibles du site restent lisibles dans des archives "
                     "publiques, même s'ils ont disparu du site : un attaquant peut y "
                     "trouver des accès ou des réglages.",
        "entreprise": "Ce qui a été publié par erreur reste consultable par n'importe qui.",
        "loi": RGPD_SECURITE + " " + RGPD_FUITE,
    },
    "archives_documents": {
        "attaquant": "Vos anciens documents restent consultables : ils donnent des noms, des "
                     "habitudes, des fournisseurs, utiles pour un faux mail crédible.",
    },
    "documents_google": {
        "attaquant": "Des documents de la société sont trouvables sur Google. Ils peuvent "
                     "révéler des noms, des fournisseurs, des prix.",
        "loi": "S'ils contiennent des données personnelles, leur publication doit être "
               "justifiée (RGPD).",
    },
    "noms_documents": {
        "attaquant": "Les fichiers publiés donnent les noms de vos salariés : un escroc "
                     "peut les citer pour rendre un faux mail crédible.",
    },
    "noms_documents_google": {
        "attaquant": "Les documents trouvés donnent les noms de vos salariés : un escroc "
                     "peut les citer pour rendre un faux mail crédible.",
    },
    "logiciels_documents": {
        "attaquant": "Les fichiers publiés révèlent vos logiciels et leurs versions : un "
                     "attaquant sait quel piège envoyer.",
    },
    "logiciels_documents_google": {
        "attaquant": "Les documents trouvés révèlent vos logiciels : un attaquant sait quel "
                     "piège envoyer.",
    },
    "gps": {
        "attaquant": "Des photos publiées donnent leur lieu exact de prise de vue : domicile, "
                     "dépôt, chantier.",
        "entreprise": "Risque de vol ou de repérage d'un lieu que vous ne vouliez pas "
                      "montrer.",
        "loi": "Si la photo révèle où vit ou travaille une personne, c'est une donnée "
               "personnelle (RGPD).",
    },
    "adresses_publiques": {
        "attaquant": "Les adresses mail visibles reçoivent du spam et des mails piégés. "
                     "Elles servent aussi à deviner le format des autres adresses.",
    },
    "portables": {
        "attaquant": "Un numéro de portable publié peut servir à des arnaques par SMS ou par "
                     "téléphone (faux banquier, faux technicien).",
        "loi": "Publier le portable d'un salarié suppose qu'il soit d'accord (RGPD).",
    },
    "numeros_phoneinfoga": {
        "attaquant": "Les numéros publiés peuvent servir à des arnaques par SMS ou appel.",
    },
    "telephone_dirigeant": {
        "attaquant": "Un portable connu permet les arnaques ciblées : faux SMS de la banque, "
                     "appel d'un faux technicien.",
    },
    "instagram": {
        "attaquant": "Un compte public renseigne sur l'équipe, les lieux et les habitudes : "
                     "de quoi rendre une arnaque crédible.",
    },
    "comptes_pseudo": {
        "attaquant": "Les comptes publics au même pseudo aident un escroc à se faire passer "
                     "pour vous ou à deviner vos questions de sécurité.",
    },
    "comptes_mail": {
        "attaquant": "Chaque compte oublié lié à votre adresse est une porte possible : s'il "
                     "est piraté, il peut servir à entrer ailleurs.",
    },
    "google_dirigeant": {
        "attaquant": "Un compte Google rattaché à votre adresse peut être visé par des faux "
                     "mails « Google ». S'il tombe, il ouvre souvent vos documents.",
    },

    # ---------------- Qualité du site ----------------
    "lenteur": {
        "entreprise": "Une page lente fait partir des visiteurs et baisse votre place sur "
                      "Google.",
    },
    "toutes_pages": {
        "entreprise": "Des pages lentes font partir des visiteurs.",
    },
    "vitesse_sitespeed": {
        "entreprise": "Une page lente fait partir des visiteurs.",
    },
    "accessibilite": {
        "entreprise": "Des personnes malvoyantes ou âgées ont du mal à utiliser votre site.",
        "loi": "Depuis le 28/06/2025, les sites de vente en ligne doivent être accessibles "
               "(directive européenne sur l'accessibilité). Les microentreprises de services "
               "(moins de 10 salariés et moins de 2 M€ de chiffre d'affaires) en sont "
               "dispensées.",
    },
}

# --- Exemples réels (pédagogiques), tous vérifiés et sourcés -----------------------
# Un exemple n'est ajouté QUE s'il existe un cas public vérifiable. Jamais de nom de
# particulier. Sources détaillées : docs/sources-consequences.md.

_EX_TLS_CNIL = {
    "texte": "En 2024, la CNIL a mis à l'amende plusieurs organismes dont les sites "
             "acceptaient encore de vieilles versions du chiffrement (TLS 1.0 ou 1.1) après "
             "une mise en demeure de les mettre à jour.",
    "source": "CNIL, 12/03/2024",
    "url": "https://www.cnil.fr/fr/la-cnil-prononce-quinze-nouvelles-sanctions-dans-le-cadre-de-la-procedure-simplifiee-depuis-janvier",
}
_EX_FAUX_VIREMENT = {
    "texte": "En 2024, une entreprise agroalimentaire du Finistère a perdu 65 000 € : une "
             "assistante a fait un virement en suivant un faux mail du « patron ». Selon "
             "Cybermalveillance.gouv.fr, les faux ordres de virement chez les professionnels "
             "ont augmenté de 29 % en 2024.",
    "source": "Clubic, 04/05/2026 (chiffres Cybermalveillance.gouv.fr)",
    "url": "https://www.clubic.com/dossier-610123-l-arnaque-au-faux-fournisseur-une-fraude-qui-cible-les-pme-et-detourne-les-virements.html",
}
_EX_RANCON = {
    "texte": "Fin 2019, le fabricant lyonnais de lingerie Lise Charmel a été bloqué par un "
             "rançongiciel : 1 150 salariés à l'arrêt, plusieurs millions d'euros de manque à "
             "gagner, puis un redressement judiciaire en février 2020.",
    "source": "Le Monde Informatique, 04/03/2020",
    "url": "https://www.lemondeinformatique.fr/actualites/lire-lise-charmel-en-redressement-judiciaire-apres-un-ransomware-78321.html",
}
_EX_MDP_CNIL = {
    "texte": "Entre juin et octobre 2026, la CNIL a sanctionné une douzaine d'organismes pour "
             "défaut de sécurité, notamment des mots de passe trop faibles et des comptes "
             "partagés pour accéder au fichier clients.",
    "source": "CNIL, 17/11/2026",
    "url": "https://cnil.fr/fr/38-sanctions-simplifiees",
}

EXEMPLES = {
    "protocoles_anciens": _EX_TLS_CNIL,
    "chiffrements_faibles": _EX_TLS_CNIL,
    "spf": _EX_FAUX_VIREMENT,
    "dmarc": _EX_FAUX_VIREMENT,
    "domaines_imitateurs": _EX_FAUX_VIREMENT,
    "assureur_personnel_sensibilise": _EX_FAUX_VIREMENT,
    "assureur_sauvegarde_testee": _EX_RANCON,
    "assureur_continuite_testee": _EX_RANCON,
    "assureur_mdp_complexes": _EX_MDP_CNIL,
}

# Questionnaire assureur : une conséquence par question (clé « assureur_<id> »).
CONSEQUENCES_ASSUREUR = {
    "mfa_distance": {
        "attaquant": "Un seul mot de passe volé (faux mail, fuite) suffit pour entrer dans "
                     "votre messagerie et vos fichiers.",
        "entreprise": "Messagerie piratée, faux virements envoyés depuis votre vraie adresse, "
                      "données volées.",
        "loi": RGPD_SECURITE + " " + RGPD_FUITE,
    },
    "sauvegarde_testee": {
        "attaquant": "Un rançongiciel chiffre tous vos fichiers et demande une rançon.",
        "entreprise": "Sans sauvegarde qui marche, l'activité peut s'arrêter des semaines. "
                      "Beaucoup de petites entreprises ne s'en relèvent pas.",
        "loi": RGPD_FUITE,
    },
    "donnees_chiffrees": {
        "attaquant": "Un ordinateur ou un disque volé donne accès à tout, en clair.",
        "entreprise": "Fichiers clients, paie, RH : revente possible, image abîmée.",
        "loi": RGPD_SECURITE + " " + RGPD_FUITE,
    },
    "maj_30j": {
        "attaquant": "Des robots cherchent en permanence les failles connues non corrigées.",
        "entreprise": "Un poste pas à jour peut suffire à faire entrer un rançongiciel.",
        "loi": RGPD_SECURITE,
    },
    "droits_admin": {
        "attaquant": "Un seul poste piégé donne la main sur toute l'entreprise.",
        "entreprise": "Une erreur de clic d'un salarié peut toucher tout le réseau.",
    },
    "mdp_complexes": {
        "attaquant": "Les mots de passe simples se devinent ou se cassent en quelques "
                     "secondes.",
        "loi": RGPD_SECURITE,
    },
    "antivirus_pare_feu": {
        "attaquant": "Même une attaque banale (pièce jointe piégée) passe sans être bloquée.",
    },
    "personnel_sensibilise": {
        "attaquant": "La plupart des attaques commencent par un mail piégé : un salarié non "
                     "averti clique.",
        "entreprise": "Faux virement, mot de passe donné, rançongiciel.",
    },
    "continuite_testee": {
        "entreprise": "Le jour d'une attaque, personne ne sait quoi faire : l'arrêt dure plus "
                      "longtemps et coûte plus cher.",
    },
    "vpn_distance": {
        "attaquant": "Un accès à distance exposé sur internet est essayé en permanence par "
                     "des robots.",
    },
    "charte_informatique": {
        "loi": "Sans charte, il est plus difficile de reprocher une faute à un salarié qui a "
               "mal utilisé l'informatique.",
    },
}
ASSURANCE_QUESTIONNAIRE = ("C'est une question de votre assureur cyber. Si vous avez répondu "
                           "« oui » alors que ce n'est pas en place, l'indemnisation peut être "
                           "réduite (Code des assurances, art. L.113-9), voire le contrat "
                           "annulé en cas de fausse déclaration volontaire (art. L.113-8).")

# Variantes d'une fiche selon la situation réelle, reconnue au titre du constat.
# Cas réel du 26/11/2026 : DMARC était en quarantaine, mais le rapport disait « rien ne
# dit aux messageries de refuser un faux mail », texte écrit pour un DMARC absent. Le
# client voit la contradiction. Les rubriques données ici remplacent celles de la fiche.
VARIANTES = {
    "dmarc": [
        (re.compile(r"quarantaine|quarantine", re.I), {
            "attaquant": "Les faux mails à votre nom sont envoyés en courrier indésirable, "
                         "mais pas refusés : ils arrivent quand même chez le destinataire. "
                         "Un client qui fouille ses indésirables, ou une messagerie qui "
                         "applique mal la consigne, peut encore se faire piéger.",
            "entreprise": "Le risque de fausse facture ou de faux ordre de virement est "
                          "réduit, mais pas supprimé : il suffit d'une personne qui sort le "
                          "faux mail des indésirables.",
        }),
    ],
}

# Constats créés sans clé : on les reconnaît à leur titre (sans toucher aux modules).
PAR_TITRE = [
    (re.compile(r"n'est pas chiffré$"), "technos_non_chiffre"),
    (re.compile(r"comptes publics probables au pseudo"), "comptes_pseudo"),
    (re.compile(r"L'adresse du dirigeant a un compte"), "comptes_mail"),
    (re.compile(r"Le numéro du dirigeant"), "telephone_dirigeant"),
]

# Le cadre général, affiché une seule fois dans le rapport (plafonds avec leur contexte).
CADRE_GENERAL = {
    "titre": "Ce que disent la loi et les assureurs",
    "points": [
        "RGPD : toute entreprise doit protéger les données personnelles qu'elle détient "
        "(art. 32) et signaler une fuite à la CNIL dans les 72 heures (art. 33). Pour un "
        "manque de sécurité, l'amende peut aller jusqu'à 10 millions d'euros ou 2 % du "
        "chiffre d'affaires mondial (art. 83) : c'est un plafond, la CNIL tient compte de "
        "la taille de l'entreprise et de la gravité.",
        "Pour les petits dossiers, la CNIL utilise une procédure simplifiée : amende de "
        "20 000 € au plus, avec rappel à l'ordre ou injonction de corriger.",
        "Code pénal (art. 226-17) : ne pas protéger des données personnelles comme l'exige "
        "le RGPD est aussi un délit. Ces poursuites restent rares et visent les cas graves.",
        "NIS2 : cette directive européenne (loi « Résilience » en cours d'adoption en "
        "France) impose plus de sécurité aux entreprises de 50 salariés ou plus, ou de plus "
        "de 10 M€ de chiffre d'affaires, dans certains secteurs. La plupart des TPE ne sont "
        "pas concernées, mais leurs gros clients leur demanderont les mêmes garanties.",
        "Assurance : pour être indemnisé d'une cyberattaque, il faut porter plainte dans "
        "les 72 heures (Code des assurances, art. L.12-10-1). Une fausse réponse au "
        "questionnaire de l'assureur peut réduire l'indemnisation (art. L.113-9) ou annuler "
        "le contrat si elle est volontaire (art. L.113-8).",
    ],
    "note": "Ce rapport n'est pas un avis juridique. En cas de doute, demandez à votre "
            "assureur ou à un avocat.",
}

RUBRIQUES = (
    ("attaquant", "Ce qu'un attaquant peut faire"),
    ("entreprise", "Ce que ça peut coûter à l'entreprise"),
    ("loi", "Côté loi"),
    ("assurance", "Côté assurance"),
)


def cle_effective(constat):
    """La clé de conséquences d'un constat (dictionnaire), même s'il a été créé sans clé."""
    cle = constat.get("cle") or ""
    if cle.startswith("marque_"):
        return "marque"
    if cle:
        return cle
    for motif, cle_titre in PAR_TITRE:
        if motif.search(constat.get("titre") or ""):
            return cle_titre
    return ""


def pour(constat):
    """Les conséquences d'un constat (dictionnaire), ou {} s'il est correct ou inconnu.
    Ne renvoie que les rubriques remplies, dans l'ordre de RUBRIQUES."""
    if constat.get("niveau") == OK:
        return {}
    cle = cle_effective(constat)
    if cle.startswith("assureur_"):
        fiche = dict(CONSEQUENCES_ASSUREUR.get(cle[len("assureur_"):], {}))
        fiche["assurance"] = ASSURANCE_QUESTIONNAIRE
    else:
        fiche = dict(CONSEQUENCES.get(cle, {}))
        for motif, rubriques in VARIANTES.get(cle, ()):
            if motif.search(constat.get("titre") or ""):
                fiche.update(rubriques)
                break
    resultat = {nom: fiche[nom] for nom, _ in RUBRIQUES if fiche.get(nom)}
    if resultat and cle in EXEMPLES:
        resultat["exemple"] = dict(EXEMPLES[cle])
    return resultat
