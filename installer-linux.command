#!/usr/bin/env bash
# Installateur Vigie pour Linux (Debian / Ubuntu / Kali).
# Double-clique dessus (ou : bash installer-linux.command).
#
# Il installe la base (Python, pipx, go, npm, git), puis demande à Vigie d'installer
# TOUS les outils non payants du catalogue d'un seul coup (python3 -m vigie installer
# --tous). Vigie essaie, pour chaque outil, la commande écrite dans sa propre
# documentation (apt / pipx / go / npm), jamais un paquet deviné sur son nom.
#
# Les outils PAYANTS (Robin, uncover, PentAGI, mcp-scan) sont écartés automatiquement.
# Les outils ACTIFS / offensifs sont installés mais Vigie ne les lance qu'avec une
# autorisation signée. Il ne touche à AUCUNE machine distante : il prépare celle-ci.
set -u

racine="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
titre() { printf "\n=== %s ===\n" "$1"; }

if command -v sudo >/dev/null; then SUDO="sudo"; $SUDO -v || true; else SUDO=""; fi
APT=""; command -v apt-get >/dev/null && APT="apt-get"

titre "Base (Python, pipx, go, npm, git, curl)"
if [ -n "$APT" ]; then
  $SUDO $APT update -y >/dev/null 2>&1
  $SUDO $APT install -y python3 python3-pip pipx golang-go nodejs npm git curl unzip jq \
    >/dev/null 2>&1 && echo "  [ok] base installée" \
    || echo "  [!] base incomplète : vérifie ta connexion internet"
else
  echo "  [!] apt introuvable : ce script vise Debian/Ubuntu/Kali"
fi
python3 -m pip install --user --upgrade pip pipx >/dev/null 2>&1 || true
python3 -m pipx ensurepath >/dev/null 2>&1 || true

titre "Vigie"
if [ -d "$racine/vigie" ]; then echo "  [ok] Vigie présent"
else echo "  [!] dossier vigie introuvable à côté de ce script"; exit 1; fi

titre "Installation de TOUS les outils non payants (ça peut prendre un moment)"
# Vigie installe tout le catalogue, outils payants écartés, et écrit un bilan.
(cd "$racine" && python3 -m vigie installer --tous --parallele 6 \
    --rapport "$HOME/vigie-installation.json")

titre "Vérification : ce que Vigie voit maintenant"
(cd "$racine" && python3 -m vigie outils 2>/dev/null | grep -i "installé" | head -40) || true

cat <<'TXT'

Terminé. Le détail outil par outil est dans :  ~/vigie-installation.json

Pour lancer Vigie (dans le navigateur) :
  python3 -m vigie interface

Onglet « Lancer un outil » : chaque outil, un par un, sur une cible.
Les outils actifs/offensifs ne partent qu'avec une autorisation signée
(onglet « Outils manuels »).
TXT
