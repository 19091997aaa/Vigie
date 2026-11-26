"""La table des failles F01 à F34 (« telle faille, telle conséquence »), vue côté client.

Source unique : `donnees_failles/pavillon-noir-failles-consequences.json`, rédigée par
Anass avec son tuteur (26/11/2026). Les deux CSV à côté (séparés par « ; », s'ouvrent dans
Excel) sont la même table : un test vérifie qu'ils disent la même chose que le JSON.

Ce module fait trois choses :
1. il relie chaque constat de Vigie (sa clé, parfois son titre) à une faille Fxx ;
2. il ne garde que les colonnes à montrer au client (jamais la phrase pour le téléphone,
   ni la place dans l'offre, ni le statut de rédaction) ;
3. il applique les garde-fous :
   - un cas réel n'est cité au client que s'il est de fiabilité « forte » ;
   - une faille de case C (accès autorisé, entretien) n'apparaît que si le client a signé
     l'autorisation ;
   - les failles de fuites (F01, F02, F34) sont traitées comme C : chercher les adresses
     d'un prospect dans des fuites est interdit à froid (CLAUDE.md, MARCHE.md §2), même si
     la table les marque « A » ;
   - une faille encore « à construire » (F33) n'est jamais montrée.
"""
import json
import os
import re

DOSSIER = os.path.join(os.path.dirname(__file__), "donnees_failles")
FICHIER = os.path.join(DOSSIER, "pavillon-noir-failles-consequences.json")

# Les colonnes qu'un rapport client peut afficher, dans l'ordre d'affichage.
RUBRIQUES = (
    ("ce_que_ca_veut_dire", "Ce que ça veut dire"),
    ("consequence_immediate", "Tout de suite"),
    ("consequence_entreprise", "Pour l'entreprise"),
    ("consequence_dirigeant", "Pour vous, dirigeant"),
    ("ce_que_ca_lui_apporte", "Ce que ce diagnostic vous apporte"),
    ("action_corrective", "Ce qu'il faut faire"),
)
COLONNES_CLIENT = ("id", "famille", "gravite", "nom_technique") + tuple(n for n, _ in RUBRIQUES)
# Réservées à l'entraînement à la vente : JAMAIS dans un rapport.
COLONNES_ENTRAINEMENT = ("phrase_telephone", "place_dans_l_offre", "statut")

# Fuites de données : interdites dans le diag gratuit à froid, quoi que dise la table.
FUITES = {"F01", "F02", "F34"}

# Correspondance constat Vigie -> faille. Clé du constat -> liste de (motif du titre ou
# de l'explication, faille). Le premier motif qui colle gagne ; None = colle toujours.
# Ce qui n'est PAS relié, exprès :
# - dmarc en quarantaine : ni F04 (absent) ni F05 (p=none) ;
# - cms : Vigie dit « tourne sous WordPress », pas « obsolète » (F16 = obsolète) ;
# - marque_* : un nom pris sur un site n'est pas encore un faux profil (F13) ;
# - F01, F02, F34 : Vigie ne cherche pas dans les fuites à froid.
CORRESPONDANCE = {
    "spf": [(None, "F03")],
    "dmarc": [(r"absent", "F04"),
              (r"p=none|simple surveillance|pas en blocage", "F05")],
    "dkim": [(None, "F06")],
    "domaines_imitateurs": [(r"recevoir du courrier", "F11"), (None, "F10")],
    "bibliotheques": [(None, "F16")],
    "certificat": [(None, "F17")],
    "certificat_www": [(None, "F17")],
    "https": [(None, "F17")],
    "technos_non_chiffre": [(None, "F17")],
    "moteurs_exposition": [(r"\b3389\b", "F19"), (r"\b(445|139|5000|5001)\b", "F20")],
    # Questionnaire assureur : failles de case C (montrées seulement sur autorisation).
    "assureur_mfa_distance": [(None, "F07")],
    "assureur_maj_30j": [(None, "F24")],
    "assureur_droits_admin": [(None, "F25")],
    "assureur_mdp_complexes": [(None, "F26")],
    "assureur_sauvegarde_testee": [(None, "F28")],
    "assureur_continuite_testee": [(None, "F30")],
}
# Clés dont le nom change avec l'adresse (https_www.exemple.fr) : on lit le début.
PREFIXES = {"https_": "https"}

_TABLE = None


def charger():
    """La table complète (méta, failles, cas réels), lue une fois."""
    global _TABLE
    if _TABLE is None:
        with open(FICHIER, encoding="utf-8") as lu:
            _TABLE = json.load(lu)
    return _TABLE


def failles():
    return {f["id"]: f for f in charger()["failles"]}


def cas_reels():
    return {c["id"]: c for c in charger()["cas_reels"]}


def identifiant(constat):
    """La faille Fxx d'un constat (dictionnaire), ou '' si aucune ne correspond."""
    cle = constat.get("cle") or ""
    for prefixe, base in PREFIXES.items():
        if cle.startswith(prefixe):
            cle = base
    texte = (constat.get("titre") or "") + " " + (constat.get("explication") or "")
    for motif, faille in CORRESPONDANCE.get(cle, ()):
        if motif is None or re.search(motif, texte, re.I):
            return faille
    return ""


def montrable(faille, autorise):
    """Les garde-fous : cette faille peut-elle apparaître dans ce rapport ?"""
    if faille.get("statut") == "a_construire":
        return False
    # « C » ou « A/C » (prudence) : seulement si le client a signé l'autorisation.
    sur_accord = faille["id"] in FUITES or "C" in (faille.get("case_juridique") or "")
    return autorise or not sur_accord


def pour(constat, autorise=False):
    """La fiche client de la faille liée au constat, ou {} (aucune, ou cachée par un
    garde-fou). Ne contient que des colonnes client et des cas « forte »."""
    fid = identifiant(constat)
    faille = failles().get(fid) if fid else None
    if not faille or not montrable(faille, autorise):
        return {}
    fiche = {nom: faille[nom] for nom in COLONNES_CLIENT if faille.get(nom)}
    tous = cas_reels()
    fiche["cas"] = [{"titre": c["titre"], "pays": c.get("pays", ""), "date": c.get("date", ""),
                     "resume": c["resume"], "sources": list(c.get("sources") or [])}
                    for c in (tous.get(i) for i in faille.get("cas_reels") or [])
                    if c and c.get("fiabilite") == "forte"]
    return fiche
