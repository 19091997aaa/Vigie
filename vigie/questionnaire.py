"""Les questions que les assureurs cyber posent vraiment, tirées des questionnaires
Hiscox CyberClear et AXA Cyber Secure (étude de marché du 20/11/2026).

C'est le cœur du produit payant : le patron coche « oui » à son assureur sans savoir
si c'est vrai. Vigie vérifie, point par point, et sort une fiche qui dit ce qui tient
et ce qui expose à un refus de garantie.

Chaque question : à qui répondre « non » fait courir un risque, et quel assureur la pose.
"""
from .modeles import CRITIQUE, IMPORTANT, INFO

# gravite_si_non : le niveau du constat quand la réponse est « non ».
QUESTIONS = [
    {"id": "mfa_distance", "gravite_si_non": CRITIQUE, "assureurs": "Hiscox, AXA",
     "question": "La double authentification est-elle active sur les accès à distance "
                 "(messagerie, Microsoft 365, VPN) ?",
     "pourquoi": "Sans elle, un mot de passe volé suffit à entrer. C'est la première "
                 "exigence des assureurs ; son absence peut faire refuser la garantie."},
    {"id": "sauvegarde_testee", "gravite_si_non": CRITIQUE, "assureurs": "Hiscox, AXA",
     "question": "Avez-vous une sauvegarde hebdomadaire, débranchée ou hors site, "
                 "dont la restauration a déjà été testée ?",
     "pourquoi": "Une sauvegarde jamais testée est une sauvegarde qu'on découvre vide "
                 "le jour d'un rançongiciel. C'est votre seule assurance de rouvrir."},
    {"id": "donnees_chiffrees", "gravite_si_non": CRITIQUE, "assureurs": "AXA",
     "question": "Les données sensibles (clients, RH, paie) sont-elles chiffrées ?",
     "pourquoi": "En cas de vol, des données chiffrées sont inutilisables ; en clair, "
                 "elles se revendent et vous exposent à une amende CNIL."},
    {"id": "maj_30j", "gravite_si_non": IMPORTANT, "assureurs": "Hiscox",
     "question": "Les logiciels et systèmes sont-ils mis à jour au moins tous les 30 jours ?",
     "pourquoi": "Les attaques automatiques visent les failles connues non corrigées. "
                 "Une mise à jour en retard, c'est une porte laissée ouverte."},
    {"id": "droits_admin", "gravite_si_non": IMPORTANT, "assureurs": "Hiscox",
     "question": "Les droits administrateur sont-ils limités aux seules personnes qui "
                 "en ont besoin ?",
     "pourquoi": "Si tout le monde est administrateur, un seul poste piégé donne les clés "
                 "de toute l'entreprise."},
    {"id": "mdp_complexes", "gravite_si_non": IMPORTANT, "assureurs": "AXA",
     "question": "Les mots de passe sont-ils complexes et renouvelés régulièrement ?",
     "pourquoi": "Les mots de passe faibles ou partagés sont cassés en quelques secondes."},
    {"id": "antivirus_pare_feu", "gravite_si_non": IMPORTANT, "assureurs": "AXA",
     "question": "Avez-vous un antivirus et un pare-feu à jour, avec protection contre "
                 "les rançongiciels ?",
     "pourquoi": "C'est la barrière de base ; sans elle, même une attaque courante passe."},
    {"id": "personnel_sensibilise", "gravite_si_non": IMPORTANT, "assureurs": "AXA",
     "question": "Vos salariés sont-ils formés ou sensibilisés aux arnaques par mail ?",
     "pourquoi": "9 attaques sur 10 commencent par un mail. Un salarié averti est votre "
                 "meilleur pare-feu."},
    {"id": "continuite_testee", "gravite_si_non": IMPORTANT, "assureurs": "AXA",
     "question": "Avez-vous un plan de reprise d'activité à jour, et l'avez-vous testé ?",
     "pourquoi": "Savoir qui appeler et quoi faire le jour J fait la différence entre "
                 "deux heures et deux semaines d'arrêt."},
    {"id": "vpn_distance", "gravite_si_non": INFO, "assureurs": "AXA",
     "question": "Les connexions à distance passent-elles par un VPN ?",
     "pourquoi": "Sans VPN, un accès distant expose directement vos machines sur internet."},
    {"id": "charte_informatique", "gravite_si_non": INFO, "assureurs": "AXA",
     "question": "Existe-t-il une charte informatique annexée au règlement intérieur ?",
     "pourquoi": "Elle encadre l'usage et vous protège juridiquement en cas de faute."},
    {"id": "prestataire_securite", "gravite_si_non": INFO, "assureurs": "AXA (informatif)",
     "question": "Travaillez-vous avec un prestataire en sécurité informatique ?",
     "pourquoi": "Les assureurs le demandent ; une réponse « non » n'est pas un défaut, "
                 "mais c'est précisément là que vous pouvez vous appuyer sur nous."},
]

PAR_ID = {q["id"]: q for q in QUESTIONS}
