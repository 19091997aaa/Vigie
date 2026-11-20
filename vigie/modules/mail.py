"""Bloc Exposition - réglages mail : peut-on envoyer un faux mail au nom de la société ?

Lecture du DNS public uniquement. Aucun accord technique requis.
"""
from .. import reseau
from ..modeles import CRITIQUE, IMPORTANT, INFO, OK, Constat

BLOC = "Exposition"
# Sélecteurs DKIM les plus courants (Google, Microsoft 365, OVH, Brevo, Mailchimp...)
SELECTEURS_DKIM = [
    "google", "selector1", "selector2", "default", "dkim", "mail",
    "k1", "k2", "s1", "s2", "ovh", "mailjet", "sib", "brevo", "zoho",
]


def _c(niveau, titre, explication, correction="", cle=""):
    return Constat(BLOC, niveau, titre, explication, correction, cle)


def _mx(domaine):
    mx = reseau.dns(domaine, "MX")
    if not mx:
        return mx, [_c(INFO, "Ce domaine ne reçoit pas de mail",
                       "Aucun serveur de réception n'est déclaré. "
                       "Le domaine peut quand même être imité pour envoyer de faux mails.")]
    return mx, [_c(OK, "Réception des mails déclarée",
                   "Serveurs trouvés : " + ", ".join(sorted(mx)))]


def _spf(domaine):
    spf = [t for t in reseau.dns(domaine, "TXT") if t.lower().startswith("v=spf1")]
    if not spf:
        return spf, [_c(
            CRITIQUE, "Aucune liste des expéditeurs autorisés (SPF absent)",
            "Les messageries ne peuvent pas vérifier qui a le droit d'envoyer un mail "
            "au nom de votre société.",
            "Publier un enregistrement SPF qui liste vos vrais services d'envoi.")]
    if len(spf) > 1:
        return spf, [_c(
            IMPORTANT, f"{len(spf)} enregistrements SPF au lieu d'un seul",
            "Avec plusieurs enregistrements, la vérification échoue : "
            "c'est comme s'il n'y en avait pas.",
            "Fusionner en un seul enregistrement.")]
    regle = spf[0].lower()
    if "+all" in regle:
        return spf, [_c(CRITIQUE, "SPF ouvert à tout le monde (+all)",
                        "La règle autorise n'importe quel serveur à envoyer en votre nom.",
                        "Remplacer +all par -all.")]
    if "?all" in regle:
        return spf, [_c(IMPORTANT, "SPF sans effet (?all)",
                        "La règle existe mais ne dit pas quoi faire des expéditeurs inconnus.",
                        "Remplacer ?all par -all.")]
    if "-all" in regle:
        return spf, [_c(OK, "SPF strict (-all)", "Les expéditeurs non listés sont refusés.")]
    if "~all" in regle:
        return spf, [_c(INFO, "SPF souple (~all)",
                        "Les expéditeurs non listés sont marqués suspects mais pas refusés. "
                        "Acceptable si DMARC est bien réglé.",
                        "Passer à -all une fois tous vos services d'envoi listés.")]
    if "redirect=" in regle:
        return spf, [_c(INFO, "SPF délégué à un autre domaine",
                        "La règle renvoie vers un autre domaine : à contrôler à la main.")]
    return spf, [_c(IMPORTANT, "SPF incomplet (pas de règle finale)",
                    "Sans règle finale, les expéditeurs inconnus ne sont pas refusés.",
                    "Terminer l'enregistrement par -all.")]


def _dmarc(domaine):
    dmarc = [t for t in reseau.dns("_dmarc." + domaine, "TXT")
             if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return dmarc, [_c(
            CRITIQUE, "Aucune consigne contre l'usurpation (DMARC absent)",
            "Un escroc peut envoyer un mail qui affiche votre adresse, par exemple une fausse "
            "facture à vos clients, sans qu'aucune messagerie ne reçoive l'ordre de le bloquer.",
            "Publier un enregistrement DMARC, d'abord en surveillance, puis en blocage.")]
    regle = dmarc[0]
    etiquettes = {}
    for morceau in regle.split(";"):
        cle, _, valeur = morceau.partition("=")
        if cle.strip():
            etiquettes[cle.strip().lower()] = valeur.strip()
    politique = etiquettes.get("p", "").lower()
    constats = []
    if politique == "none":
        constats.append(_c(
            IMPORTANT, "DMARC en simple surveillance (p=none)",
            "Les faux mails à votre nom sont comptés mais toujours livrés.",
            "Passer à p=quarantine puis p=reject après lecture des rapports."))
    elif politique == "quarantine":
        constats.append(_c(OK, "DMARC en quarantaine",
                           "Les faux mails à votre nom partent en courrier indésirable.",
                           "Viser p=reject pour un blocage complet."))
    elif politique == "reject":
        constats.append(_c(OK, "DMARC en blocage (p=reject)",
                           "Les faux mails à votre nom sont refusés."))
    else:
        constats.append(_c(IMPORTANT, "DMARC mal formé",
                           "La consigne est illisible pour les messageries : " + regle,
                           "Corriger la syntaxe de l'enregistrement."))
    if "rua" not in etiquettes:
        constats.append(_c(
            INFO, "Pas d'adresse de rapport DMARC",
            "Vous ne recevez aucun rapport sur les tentatives d'usurpation.",
            "Ajouter une adresse rua= pour recevoir les rapports."))
    return dmarc, constats


def _dkim(domaine):
    trouves = []
    for selecteur in SELECTEURS_DKIM:
        nom = f"{selecteur}._domainkey.{domaine}"
        if reseau.dns(nom, "TXT") or reseau.dns(nom, "CNAME"):
            trouves.append(selecteur)
    if trouves:
        return trouves, [_c(OK, "Signature des mails trouvée (DKIM)",
                            "Sélecteurs détectés : " + ", ".join(trouves))]
    return trouves, [_c(
        INFO, "Signature des mails non trouvée (DKIM)",
        "Aucune signature avec les noms courants. Elle peut exister sous un autre nom : "
        "à confirmer en regardant l'en-tête d'un mail envoyé par la société.")]


def analyser(cible):
    """Renvoie (liste de constats, données brutes)."""
    domaine = cible.domaine
    mx, c_mx = _mx(domaine)
    spf, c_spf = _spf(domaine)
    dmarc, c_dmarc = _dmarc(domaine)
    dkim, c_dkim = _dkim(domaine)
    # Clés de convergence : permettent de recouper avec un autre outil (checkdmarc).
    for constat in c_spf:
        constat.cle = "spf"
    for constat in c_dmarc:
        constat.cle = "dmarc"
    for constat in c_dkim:
        constat.cle = "dkim"
    for constat in c_mx:
        constat.cle = "mx"
    brut = {"mx": mx, "spf": spf, "dmarc": dmarc, "dkim_selecteurs": dkim}
    return c_spf + c_dmarc + c_dkim + c_mx, brut
