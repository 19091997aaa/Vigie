"""La clé d'IA d'Anass, gardée une fois pour tous les outils d'IA.

Demande d'Anass (28/11/2026) : « je vois pas où Vigie me propose d'entrer une clé. On me
demande la clé, je la rentre. » PentestGPT, Strix, Shannon, ARTEX, PentAGI et RedAmon
lisent tous une clé d'IA dans l'environnement. Vigie la demande UNE fois (onglet
« Ouvrir un outil », partie « Ta clé d'IA »), la garde sur cette machine et la donne à
chaque outil d'IA qu'il ouvre.

Où : ~/.config/vigie/cles-ia.env (droits 600 : lisible par ton compte seulement),
JAMAIS dans le dossier de Vigie ni sur GitHub. La clé n'est jamais réaffichée en entier
(seulement ses 4 derniers caractères) ni écrite dans un journal.
"""
import os
import re

# Fournisseur -> (nom affiché, variable lue par les outils, préfixe du modèle pour Strix).
FOURNISSEURS = {
    "anthropic": ("Anthropic (Claude)", "ANTHROPIC_API_KEY", "anthropic"),
    "openai": ("OpenAI (ChatGPT)", "OPENAI_API_KEY", "openai"),
    "gemini": ("Google (Gemini)", "GEMINI_API_KEY", "gemini"),
    "deepseek": ("DeepSeek", "DEEPSEEK_API_KEY", "deepseek"),
}

# Une clé, c'est des lettres, chiffres, tirets, points, soulignés. Rien d'autre : le
# fichier est lu par bash (« source »), un guillemet ou un « $ » y serait dangereux.
_CLE = re.compile(r"[A-Za-z0-9_.\-]{16,300}")
_MODELE = re.compile(r"[A-Za-z0-9_.:/\-]{1,120}")


class Refus(Exception):
    """La clé ou le réglage n'est pas accepté : raison en français."""


def fichier():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "vigie", "cles-ia.env")


def lire():
    """{"fournisseur", "cle", "modele"} ou None si aucune clé n'est enregistrée."""
    try:
        with open(fichier(), encoding="utf-8") as f:
            texte = f.read()
    except OSError:
        return None
    valeurs = dict(re.findall(r"^export (\w+)='([^']*)'$", texte, re.M))
    fournisseur = valeurs.get("VIGIE_IA_FOURNISSEUR", "")
    if fournisseur not in FOURNISSEURS:
        return None
    cle = valeurs.get(FOURNISSEURS[fournisseur][1], "")
    if not cle:
        return None
    return {"fournisseur": fournisseur, "cle": cle,
            "modele": valeurs.get("VIGIE_IA_MODELE", "")}


def enregistrer(fournisseur, cle, modele=""):
    """Garde la clé (remplace l'ancienne). Lève Refus si elle n'a pas l'air d'une clé."""
    cle = (cle or "").strip()
    modele = (modele or "").strip()
    if fournisseur not in FOURNISSEURS:
        raise Refus("Choisis le fournisseur de ta clé (Anthropic, OpenAI, Google ou "
                    "DeepSeek).")
    if not _CLE.fullmatch(cle):
        raise Refus("Ça ne ressemble pas à une clé d'IA. Copie-la en entier depuis le site "
                    "du fournisseur (sans espace ni guillemet), puis colle-la ici.")
    if modele and not _MODELE.fullmatch(modele):
        raise Refus("Le nom du modèle ne doit contenir que des lettres, des chiffres et "
                    "les signes - . / :")
    nom, variable, prefixe = FOURNISSEURS[fournisseur]
    if modele and "/" not in modele:
        modele = f"{prefixe}/{modele}"
    lignes = ["# Clé d'IA enregistrée par Vigie (onglet « Ouvrir un outil »). Ne pas "
              "partager.",
              f"export VIGIE_IA_FOURNISSEUR='{fournisseur}'",
              f"export {variable}='{cle}'",
              # Strix lit LLM_API_KEY + STRIX_LLM.
              f"export LLM_API_KEY='{cle}'"]
    if modele:
        lignes += [f"export VIGIE_IA_MODELE='{modele}'", f"export STRIX_LLM='{modele}'"]
    chemin = fichier()
    os.makedirs(os.path.dirname(chemin), mode=0o700, exist_ok=True)
    descripteur = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descripteur, "w", encoding="utf-8") as f:
        f.write("\n".join(lignes) + "\n")
    os.chmod(chemin, 0o600)
    return f"Clé {nom} enregistrée (finit par …{cle[-4:]}). Les outils d'IA s'en servent."


def effacer():
    try:
        os.remove(fichier())
        return "Clé d'IA effacée de cette machine."
    except FileNotFoundError:
        return "Aucune clé d'IA n'était enregistrée."


def environnement():
    """Les variables à donner aux outils d'IA (vide sans clé)."""
    cle = lire()
    if not cle:
        return {}
    variables = {FOURNISSEURS[cle["fournisseur"]][1]: cle["cle"], "LLM_API_KEY": cle["cle"]}
    if cle["modele"]:
        variables["STRIX_LLM"] = cle["modele"]
    return variables


def resume():
    """Une ligne pour l'écran : quelle clé est enregistrée (sans la montrer)."""
    cle = lire()
    if not cle:
        return ""
    texte = f"{FOURNISSEURS[cle['fournisseur']][0]}, finit par …{cle['cle'][-4:]}"
    if cle["modele"]:
        texte += f", modèle {cle['modele']}"
    return texte
