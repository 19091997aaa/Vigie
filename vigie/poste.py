"""Vérifier un poste (ordinateur) : l'outil de l'offre sécurisation.

À lancer SUR l'ordinateur à vérifier, par son propriétaire ou avec son accord. Rien
n'est modifié ni supprimé : les trois outils ne font que lire.
  - ClamAV : les virus et logiciels malveillants courants (base de signatures publique) ;
  - YARA, avec les règles publiques « signature-base » : les outils de pirates plus
    ciblés. Comparés le 21/11/2026 : ils se complètent, et tous deux repèrent le fichier
    de test standard EICAR ;
  - Lynis : les réglages de sécurité du système (note de durcissement).

    python3 -m vigie poste --dossier ~/Downloads
"""
import os
import re
import subprocess

from . import outils

DONNEES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "donnees")
BASE_CLAMAV = os.path.join(DONNEES, "clamav")
REGLES_YARA = os.path.join(DONNEES, "signature-base")
DEPOT_REGLES = "https://github.com/Neo23x0/signature-base.git"
# Règles de signature-base qui exigent des variables propres à l'outil THOR : écartées.
REGLES_EXCLUES = ("generic_anomalies", "general_cloaking", "gen_webshells_ext_vars",
                  "thor_inverse_matches", "yara_mixed_ext_vars", "configured_vulns_ext_vars",
                  "gen_fake_amsi_dll", "expl_citrix_netscaler_adc_exploitation_cve_2023_3519",
                  "expl_connectwise_screenconnect_vuln_feb24", "gen_mal_3cx_compromise_mar23",
                  "yara-rules_vuln_drivers_strict_renamed", "gen_susp_obfuscation", "gen_vcruntime")


def preparer(journal=print):
    """Télécharge ou met à jour la base ClamAV et les règles YARA (données, pas de code)."""
    os.makedirs(BASE_CLAMAV, exist_ok=True)
    if outils.trouver("freshclam"):
        configuration = os.path.join(DONNEES, "freshclam.conf")
        with open(configuration, "w", encoding="utf-8") as fichier:
            fichier.write(f"DatabaseDirectory {BASE_CLAMAV}\nDatabaseMirror database.clamav.net\n")
        journal("Mise à jour de la base de virus (ClamAV)…")
        subprocess.run([outils.trouver("freshclam"), f"--config-file={configuration}",
                        f"--datadir={BASE_CLAMAV}"], capture_output=True, timeout=900)
    if outils.trouver("git"):
        journal("Mise à jour des règles YARA…")
        if os.path.isdir(os.path.join(REGLES_YARA, ".git")):
            subprocess.run(["git", "-C", REGLES_YARA, "pull", "-q", "--ff-only"],
                           capture_output=True, timeout=300)
        else:
            subprocess.run(["git", "clone", "-q", "--depth", "1", DEPOT_REGLES, REGLES_YARA],
                           capture_output=True, timeout=600)


def regles_yara(dossier=REGLES_YARA):
    chemin = os.path.join(dossier, "yara")
    if not os.path.isdir(chemin):
        return []
    return sorted(os.path.join(chemin, nom) for nom in os.listdir(chemin)
                  if nom.endswith(".yar") and nom[:-4] not in REGLES_EXCLUES)


def lire_clamav(texte):
    """« /chemin: Nom-Du-Virus FOUND » -> [(chemin, nom)]."""
    return [(m.group(1), m.group(2)) for m in
            re.finditer(r"^(.+?): (\S+) FOUND$", texte or "", re.M)]


def lire_yara(texte):
    """« NomDeRegle /chemin » -> [(chemin, règle)]."""
    trouves = []
    for ligne in (texte or "").splitlines():
        regle, _, chemin = ligne.strip().partition(" ")
        if regle and chemin:
            trouves.append((chemin, regle))
    return trouves


def lire_lynis(texte):
    indice = re.search(r"Hardening index\s*:\s*(\d+)", texte or "")
    alertes = re.findall(r"^\s*!\s+(.+)$", texte or "", re.M)
    return {"note": int(indice.group(1)) if indice else None, "alertes": alertes}


def verifier(dossier, journal=print):
    """Lance les trois outils installés. Renvoie le compte rendu (dictionnaire)."""
    dossier = os.path.abspath(os.path.expanduser(dossier))
    if not os.path.isdir(dossier):
        raise ValueError(f"Dossier introuvable : {dossier}")
    resultat = {"dossier": dossier, "clamav": None, "yara": None, "lynis": None}
    if outils.trouver("clamscan") and os.path.isdir(BASE_CLAMAV) and os.listdir(BASE_CLAMAV):
        journal("ClamAV lit les fichiers…")
        sortie = subprocess.run([outils.trouver("clamscan"), "-r", "-i", f"--database={BASE_CLAMAV}",
                                 "--max-filesize=100M", "--max-scansize=300M", dossier],
                                capture_output=True, text=True, errors="replace", timeout=7200).stdout
        resultat["clamav"] = lire_clamav(sortie)
    regles = regles_yara()
    if outils.trouver("yara") and regles:
        journal(f"YARA lit les fichiers avec {len(regles)} jeux de règles…")
        sortie = subprocess.run([outils.trouver("yara"), "-r", "-w", "-p", "4"] + regles + [dossier],
                                capture_output=True, text=True, errors="replace", timeout=7200).stdout
        resultat["yara"] = lire_yara(sortie)
    if outils.trouver("lynis"):
        journal("Lynis vérifie les réglages du système…")
        sortie = subprocess.run([outils.trouver("lynis"), "audit", "system", "--quick",
                                 "--no-colors"], capture_output=True, text=True,
                                errors="replace", timeout=1800).stdout
        resultat["lynis"] = lire_lynis(sortie)
    return resultat


def en_texte(resultat):
    lignes = [f"VÉRIFICATION DU POSTE — dossier lu : {resultat['dossier']}", ""]
    for nom, cle, quoi in (("ClamAV", "clamav", "virus courants"),
                           ("YARA", "yara", "outils de pirates")):
        trouves = resultat[cle]
        if trouves is None:
            lignes.append(f"{nom} ({quoi}) : non lancé (outil ou base absents).")
        elif not trouves:
            lignes.append(f"{nom} ({quoi}) : rien trouvé.")
        else:
            lignes.append(f"{nom} ({quoi}) : {len(trouves)} fichier(s) suspect(s) — "
                          "NE PAS les ouvrir, et faire vérifier :")
            lignes += [f"   - {chemin} ({nom_menace})" for chemin, nom_menace in trouves[:30]]
    lynis = resultat["lynis"]
    if lynis is None:
        lignes.append("Lynis (réglages du système) : non lancé.")
    else:
        lignes.append(f"Lynis (réglages du système) : note de durcissement {lynis['note']}/100, "
                      f"{len(lynis['alertes'])} alerte(s) grave(s).")
    return "\n".join(lignes)
