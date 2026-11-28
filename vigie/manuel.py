"""Les outils manuels : lancés un par un, à la main, jamais dans le diagnostic automatique.

Ce sont des contrôles ACTIFS (scan de ports, recherche de failles) : ils touchent les
machines de la cible. Avant chaque lancement, Vigie exige, dans cet ordre :
  1. un outil connu de cette liste (rien d'autre ne peut être lancé d'ici) ;
  2. la fiche de l'autorisation (autorisation_<n°>.json, voir mandat.py) : la cible,
     le type de test et la date du jour doivent y être couverts ;
  3. l'autorisation SIGNÉE (scan ou PDF) : son empreinte est notée ;
  4. une confirmation : retaper la cible, pour ne jamais attaquer la mauvaise adresse.
Chaque lancement, et chaque refus, est inscrit au journal (journal/lancements.jsonl) :
on peut prouver ce qui a été fait, quand, sur quoi, avec quelle autorisation.

Les outils offensifs de la famille GATE (sqlmap, hydra, Metasploit...) ne sont pas
dans cette liste pour l'instant : ils viendront après les essais sur le serveur
d'entraînement d'Anass.
"""
import datetime
import json
import os
import re

from . import autorisation, mandat, mes_cibles, outils
from .modeles import ControleImpossible

# nom -> catalogue (outils.CATALOGUE), type de test de l'autorisation, arguments, rôle.
OUTILS = {
    "nmap": {"outil": "nmap", "test": "ports",
             "arguments": ["-sT", "-Pn", "-T3", "--top-ports", "1000", "-sV", "--version-light",
                           "-oX", "-", "{cible}"],
             "role": "Quels services la cible ouvre sur internet (1 000 ports les plus courants)"},
    "nuclei": {"outil": "nuclei", "test": "failles",
               "arguments": ["-u", "{cible}", "-jsonl", "-silent", "-rate-limit", "20",
                             "-severity", "medium,high,critical"],
               "role": "Failles connues sur les sites et services de la cible"},
    "naabu": {"outil": "naabu", "test": "ports",
              "arguments": ["-host", "{cible}", "-json", "-silent", "-rate", "200",
                            "-top-ports", "1000"],
              "role": "Quelles portes la cible ouvre sur le réseau (1 000 ports les plus courants)"},
    "sslscan": {"outil": "sslscan", "test": "failles",
                "arguments": ["--xml=-", "--no-colour", "{cible}"],
                "role": "Versions du chiffrement et certificat acceptés par le site"},
    "nikto": {"outil": "nikto", "test": "failles",
              "arguments": ["-h", "https://{cible}", "-ask", "no", "-maxtime", "600s"],
              "role": "Serveur web : fichiers dangereux, logiciels obsolètes, en-têtes manquants"},
    "katana": {"outil": "katana", "test": "manuels",
               "arguments": ["-u", "https://{cible}", "-jsonl", "-silent", "-d", "2",
                             "-timeout", "10", "-rate-limit", "50"],
               "role": "Cartographie du site : pages et points d'entrée (formulaires, paramètres)"},
    "tlsx": {"outil": "tlsx", "test": "failles",
             "arguments": ["-u", "{cible}", "-json", "-silent", "-san", "-cn",
                           "-ex", "-ss", "-mm", "-re"],
             "role": "Certificat du site : expiré, auto-signé, mauvais nom, révoqué"},
}
CIBLE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}")


class Refus(ControleImpossible):
    """Le lancement est refusé : la raison est donnée en clair et inscrite au journal."""


def _journal(dossier, entree):
    os.makedirs(dossier, exist_ok=True)
    entree = dict(entree, quand=datetime.datetime.now().isoformat(timespec="seconds"))
    with open(os.path.join(dossier, "lancements.jsonl"), "a", encoding="utf-8") as fichier:
        fichier.write(json.dumps(entree, ensure_ascii=False) + "\n")


def lancer(nom, cible, fiche, signee, confirmation, journal="journal", jour=None, delai=1800,
           dossier_cibles=None):
    """Lance un outil manuel si tout est en règle. Renvoie le chemin de la sortie.

    Sans fiche d'autorisation, la cible doit être une des PROPRES cibles d'Anass,
    prouvée (mes_cibles.py, dans dossier_cibles) : son domaine prouvé par le DNS ou une
    VM de labo à adresse privée. Sinon : refus, autorisation signée obligatoire."""
    cible = (cible or "").strip().lower()
    trace = {"outil": nom, "cible": cible, "fiche": os.path.basename(fiche or "")}
    try:
        if nom not in OUTILS:
            raise Refus(f"Outil inconnu des outils manuels : {nom}")
        if not CIBLE.fullmatch(cible):
            raise Refus(f"Cible invalide : {cible!r} (un nom de domaine ou une adresse IP)")
        if not fiche:
            raison = (mes_cibles.raison_refus(dossier_cibles, cible) if dossier_cibles
                      else "Il faut la fiche de l'autorisation (autorisation_<n°>.json).")
            if raison:
                raise Refus(raison)
            trace["autorisation"] = "propre cible (" + mes_cibles.ATTESTATION + ")"
        else:
            lue = mandat.lire(fiche)
            trace["autorisation"] = lue.get("numero", "")
            raison = mandat.couvre(lue, cible, OUTILS[nom]["test"], jour)
            if raison:
                raise Refus(raison)
            trace.update(autorisation.verifier(signee))  # l'autorisation signée, par empreinte
        if (confirmation or "").strip().lower() != cible:
            raise Refus("Confirmation manquante : retaper exactement la cible pour lancer.")
    except ControleImpossible as refus:
        _journal(journal, dict(trace, resultat="refusé", raison=str(refus)))
        raise Refus(str(refus))

    arguments = [a.replace("{cible}", cible) for a in OUTILS[nom]["arguments"]]
    _journal(journal, dict(trace, resultat="lancé"))
    sortie = outils.executer(OUTILS[nom]["outil"], arguments, delai=delai)
    instant = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    chemin = os.path.join(journal, f"{instant}_{nom}_{cible}.txt")
    with open(chemin, "w", encoding="utf-8") as fichier:
        fichier.write(sortie or "")
    _journal(journal, dict(trace, resultat="fini", sortie=os.path.basename(chemin)))
    return chemin
