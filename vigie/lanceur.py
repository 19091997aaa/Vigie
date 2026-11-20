"""Lancer en série beaucoup d'outils sur une même cible, pour les comparer.

Sans ça, tester 222 outils est impossible : personne ne lance 222 commandes à la
main. Chaque outil n'a pas besoin d'un traducteur, seulement d'une ligne de
déclaration : sa commande et ses arguments, avec {cible} là où va le domaine.

On chronomètre chaque outil, parce qu'un outil qui trouve une seule chose en
dix minutes est un mauvais marché face à un outil qui trouve tout en dix secondes.

Rien n'est lancé via un shell : les arguments sont passés en liste, donc une
valeur saisie ne peut pas devenir une commande.
"""
import os
import shutil
import subprocess
import time

# Une ligne par outil. « facettes » dit à quelle question l'outil répond.
# Ces lignes sont des déclarations à vérifier : le premier lancement les valide.
LANCEMENTS = {
    "subfinder":   {"commande": "subfinder", "arguments": ["-silent", "-d", "{cible}"],
                    "facettes": ["domaines"]},
    "amass":       {"commande": "amass", "arguments": ["enum", "-passive", "-d", "{cible}"],
                    "facettes": ["domaines"]},
    "dnsx":        {"commande": "dnsx", "arguments": ["-silent", "-d", "{cible}", "-recon"],
                    "facettes": ["domaines", "ip"]},
    "assetfinder": {"commande": "assetfinder", "arguments": ["--subs-only", "{cible}"],
                    "facettes": ["domaines"]},
    "dnsrecon":    {"commande": "dnsrecon", "arguments": ["-d", "{cible}"],
                    "facettes": ["domaines", "ip"]},
    "dnstwist":    {"commande": "dnstwist", "arguments": ["--format", "json", "--registered",
                                                          "{cible}"],
                    "facettes": ["domaines"]},
    "theHarvester": {"commande": "theHarvester", "arguments": ["-d", "{cible}", "-b", "duckduckgo"],
                     "facettes": ["mails", "domaines"]},
    "httpx":       {"commande": "httpx", "arguments": ["-silent", "-u", "{cible}"],
                    "facettes": ["urls"]},
    "whatweb":     {"commande": "whatweb", "arguments": ["--no-errors", "{cible}"],
                    "facettes": ["urls"]},
}


def pour_facette(facette):
    """Les outils déclarés qui répondent à cette question."""
    return [nom for nom, ligne in LANCEMENTS.items() if facette in ligne["facettes"]]


def installe(nom):
    ligne = LANCEMENTS.get(nom)
    return bool(ligne) and shutil.which(ligne["commande"]) is not None


def lancer_un(nom, cible, delai=300):
    """Lance un outil sur la cible. Renvoie un compte rendu, sans jamais lever d'erreur."""
    ligne = LANCEMENTS.get(nom)
    if not ligne:
        return {"outil": nom, "lance": False, "raison": "non déclaré", "secondes": 0, "sortie": ""}
    chemin = shutil.which(ligne["commande"])
    if not chemin:
        return {"outil": nom, "lance": False, "raison": "pas installé", "secondes": 0, "sortie": ""}
    arguments = [a.replace("{cible}", cible) for a in ligne["arguments"]]
    depart = time.monotonic()
    try:
        fini = subprocess.run([chemin] + arguments, capture_output=True, text=True,
                              timeout=delai, errors="replace")
    except subprocess.TimeoutExpired:
        return {"outil": nom, "lance": False, "raison": f"dépassement de {delai} s",
                "secondes": round(time.monotonic() - depart, 1), "sortie": ""}
    secondes = round(time.monotonic() - depart, 1)
    sortie = (fini.stdout or "") + ("\n" + fini.stderr if fini.returncode else "")
    # Un outil qui sort en erreur, ou qui n'affiche rien, n'a rien mesuré : on le marque.
    # Sans ça, le message d'erreur (qui contient souvent la cible) passerait pour une trouvaille.
    echoue = fini.returncode != 0 or not (fini.stdout or "").strip()
    return {"outil": nom, "lance": True, "echoue": echoue, "raison": "", "secondes": secondes,
            "code": fini.returncode, "sortie": sortie}


def lancer_tous(noms, cible, dossier, delai=300, journal=print):
    """Lance chaque outil et écrit sa sortie dans dossier/<outil>.txt. Renvoie les comptes rendus."""
    os.makedirs(dossier, exist_ok=True)
    comptes = []
    for numero, nom in enumerate(noms, 1):
        journal(f"[{numero}/{len(noms)}] {nom}…")
        resultat = lancer_un(nom, cible, delai)
        if resultat["lance"]:
            chemin = os.path.join(dossier, f"{nom}.txt")
            with open(chemin, "w", encoding="utf-8") as fichier:
                fichier.write(resultat["sortie"])
            journal(f"    {resultat['secondes']} s, {len(resultat['sortie'])} caractères")
        else:
            journal(f"    écarté : {resultat['raison']}")
        comptes.append({k: v for k, v in resultat.items() if k != "sortie"})
    return comptes


def temps_par_outil(comptes):
    """Le chronomètre, pour arbitrer : un outil lent qui apporte peu est un mauvais marché."""
    return {c["outil"]: c["secondes"] for c in comptes if c["lance"]}
