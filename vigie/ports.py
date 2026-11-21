"""Traduire un scan de ports (Nmap, format XML) en français de patron.

Sert au bloc « Réseau et postes » : ce qu'un intrus branché sur le Wi-Fi verrait.
Le scan lui-même est un contrôle ACTIF : il n'est jamais lancé par Vigie tout seul.
Il est lancé par la personne qui a le droit de le faire (son propre réseau, ou un
client qui a signé l'autorisation), par exemple avec essais/scanner-ma-maison.command.

    python3 -m vigie.ports essais/resultats/mac.xml essais/resultats/portes.xml
"""
import sys
import xml.etree.ElementTree as ET

from .modeles import CRITIQUE, IMPORTANT, INFO, OK

# Port -> (niveau, ce que c'est, pourquoi ça compte). Inconnu = INFO, à identifier.
PORTS = {
    21: (IMPORTANT, "partage de fichiers à l'ancienne (FTP)",
         "Les mots de passe y circulent en clair."),
    22: (INFO, "accès à distance en ligne de commande (SSH)",
         "Normal sur un serveur ; sur un poste ou un objet, à fermer s'il ne sert pas."),
    23: (CRITIQUE, "accès à distance sans chiffrement (Telnet)",
         "Tout passe en clair, mot de passe compris : à fermer immédiatement."),
    53: (OK, "annuaire du réseau (DNS)", "Normal sur la box."),
    80: (INFO, "page web (souvent l'administration de l'appareil)",
         "Vérifier que le mot de passe d'origine a été changé."),
    135: (INFO, "service interne de Windows (RPC)", "Normal sur un PC Windows, jamais vers internet."),
    5357: (INFO, "découverte des PC et imprimantes Windows (WSD)",
           "Normal sur un réseau de maison ; à couper sur un Wi-Fi public."),
    8008: (OK, "diffusion vers la télé (Chromecast / Google Cast)", "Normal sur une box TV."),
    8009: (OK, "diffusion vers la télé (Chromecast / Google Cast)", "Normal sur une box TV."),
    139: (IMPORTANT, "partage de fichiers Windows (ancien)",
          "Cible favorite des virus qui se propagent d'un poste à l'autre."),
    443: (OK, "page web chiffrée (administration de l'appareil)",
          "Normal ; vérifier que le mot de passe d'origine a été changé."),
    445: (IMPORTANT, "partage de fichiers Windows (SMB)",
          "Cible favorite des rançongiciels qui se propagent d'un poste à l'autre."),
    548: (INFO, "partage de fichiers Apple (AFP)", "À couper s'il ne sert pas."),
    554: (IMPORTANT, "flux vidéo (caméra, RTSP)",
          "Une caméra mal protégée peut être regardée par n'importe qui sur le réseau."),
    631: (INFO, "imprimante partagée (IPP)", "Normal pour une imprimante."),
    1900: (INFO, "découverte automatique des appareils (UPnP)",
           "Pratique, mais permet à un appareil d'ouvrir seul des portes vers internet."),
    3389: (CRITIQUE, "bureau à distance Windows (RDP)",
           "Première porte d'entrée des rançongiciels : jamais ouvert sans protection."),
    5000: (INFO, "récepteur AirPlay (Mac) ou administration (NAS)",
           "Tout appareil du Wi-Fi peut le voir ; à couper s'il ne sert pas."),
    5900: (IMPORTANT, "partage d'écran (VNC)",
           "Permet de prendre la main sur l'écran : mot de passe fort obligatoire."),
    7000: (INFO, "récepteur AirPlay", "Tout appareil du Wi-Fi peut le voir ; à couper s'il ne sert pas."),
    8080: (INFO, "page web d'administration", "Vérifier que le mot de passe d'origine a été changé."),
    8443: (INFO, "page web d'administration chiffrée",
           "Vérifier que le mot de passe d'origine a été changé."),
    9100: (INFO, "imprimante réseau", "Normal pour une imprimante."),
    62078: (OK, "synchronisation d'iPhone", "Normal sur un iPhone ou un iPad."),
}
INCONNU = (INFO, "service non identifié", "À identifier : un service inconnu est un service oublié.")


def lire_nmap(chemin):
    """[{ip, nom, ports: [{port, service, produit}]}] pour chaque appareil vu."""
    appareils = []
    # Fichier produit par Nmap sur la machine elle-même, pas une donnée reçue d'un tiers ;
    # ElementTree ne charge pas les entités externes (Python 3.7.1+). Semgrep, 21/11/2026.
    for hote in ET.parse(chemin).getroot().iter("host"):  # nosemgrep
        etat = hote.find("status")
        if etat is not None and etat.get("state") != "up":
            continue
        ip = next((a.get("addr") for a in hote.iter("address") if a.get("addrtype") == "ipv4"), "")
        nom = next((h.get("name") for h in hote.iter("hostname")), "")
        ports = []
        for port in hote.iter("port"):
            if (port.find("state") is None or port.find("state").get("state") != "open"):
                continue
            service = port.find("service")
            ports.append({
                "port": int(port.get("portid")),
                "service": service.get("name", "") if service is not None else "",
                "produit": " ".join(filter(None, [service.get("product", ""),
                                                  service.get("version", "")]))
                           if service is not None else "",
            })
        appareils.append({"ip": ip, "nom": nom, "ports": ports})
    return appareils


def traduire(appareils):
    """Une ligne en français par porte ouverte, du plus grave au moins grave."""
    ordre = {CRITIQUE: 0, IMPORTANT: 1, INFO: 2, OK: 3}
    lignes = []
    for appareil in appareils:
        qui = appareil["nom"] or appareil["ip"]
        for p in appareil["ports"]:
            niveau, quoi, pourquoi = PORTS.get(p["port"], INCONNU)
            detail = f" ({p['produit']})" if p["produit"] else ""
            lignes.append((ordre[niveau], niveau, f"{qui} : porte {p['port']}, {quoi}{detail}. {pourquoi}"))
    return [(niveau, texte) for _, niveau, texte in sorted(lignes, key=lambda l: l[0])]


if __name__ == "__main__":
    for fichier in sys.argv[1:]:
        print(f"== {fichier}")
        for niveau, texte in traduire(lire_nmap(fichier)):
            print(f"[{niveau}] {texte}")
