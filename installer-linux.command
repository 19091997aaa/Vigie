#!/usr/bin/env bash
# Installateur Vigie pour Linux (Debian / Ubuntu / Kali).
# Double-clique dessus, ou :  bash installer-linux.command [dossier]
#
# Il installe la base (Python, pipx, go, npm, git), ATTEND si une mise à jour
# automatique occupe apt, VÉRIFIE que pipx/go/npm répondent vraiment, puis demande
# à Vigie d'installer TOUS les outils non payants du catalogue d'un seul coup.
# Vigie essaie, pour chaque outil, la commande écrite dans sa propre documentation
# (apt / pipx / go / npm), jamais un paquet deviné sur son nom.
#
# Argument optionnel : le dossier où poser les outils (ex. /opt/vigie-outils, un disque
# dédié). Sans argument, les outils vont dans les emplacements par défaut (~/.local, ~/go).
#
# Les outils PAYANTS (Robin, uncover, PentAGI, mcp-scan) sont écartés automatiquement.
# Les outils ACTIFS / offensifs sont installés mais Vigie ne les lance qu'avec une
# autorisation signée. Il ne touche à AUCUNE machine distante : il prépare celle-ci.
set -u

racine="$(cd "$(dirname "$0")" && pwd)"
dest="${1:-}"                       # dossier des outils (optionnel)
export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/lib/go/bin:$PATH"
[ -n "$dest" ] && export PATH="$dest/bin:$PATH"
titre() { printf "\n=== %s ===\n" "$1"; }

if command -v sudo >/dev/null; then SUDO="sudo"; $SUDO -v || true; else SUDO=""; fi
APT=""; command -v apt-get >/dev/null && APT="apt-get"

attendre_apt() {
  # Juste après le démarrage, les mises à jour automatiques (unattended-upgrades)
  # tiennent le verrou de dpkg. On attend qu'il se libère (jusqu'à ~3 min) au lieu
  # d'échouer tout de suite avec « Impossible d'obtenir le verrou de dpkg ».
  local i=0
  while $SUDO fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || $SUDO fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
     || $SUDO fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    [ "$i" -eq 0 ] && echo "  … une mise à jour automatique occupe apt, j'attends qu'elle finisse"
    sleep 5; i=$((i + 1))
    if [ "$i" -ge 36 ]; then echo "  [!] apt encore occupé après 3 min, je tente quand même"; break; fi
  done
}

titre "Base (Python, pipx, go, npm, git, curl)"
if [ -z "$APT" ]; then
  echo "  [!] apt introuvable : ce script vise Debian/Ubuntu/Kali"; exit 1
fi
attendre_apt
$SUDO $APT update -y >/dev/null 2>&1 || true
attendre_apt
$SUDO $APT install -y python3 python3-pip pipx golang-go npm git curl unzip jq \
  || echo "  [!] apt a signalé un souci ; je vérifie quand même les outils de base"

# Secours : si pipx n'est pas venu par apt (vieilles versions), on le pose via pip.
if ! command -v pipx >/dev/null 2>&1; then
  python3 -m pip install --user --upgrade pipx >/dev/null 2>&1 || true
fi
python3 -m pipx ensurepath >/dev/null 2>&1 || true
export PATH="$HOME/.local/bin:$PATH"

titre "Vérification des outils de base"
manque=""
for o in pipx go npm; do
  if command -v "$o" >/dev/null 2>&1; then
    echo "  [ok] $o"
  else
    echo "  [MANQUE] $o"; manque="$manque $o"
  fi
done
if [ -n "$manque" ]; then
  echo
  echo "  Outils de base manquants :$manque"
  echo "  apt était sans doute encore occupé. Attends une minute et relance ce script."
  exit 1
fi

titre "Vigie"
if [ -d "$racine/vigie" ]; then echo "  [ok] Vigie présent"
else echo "  [!] dossier vigie introuvable à côté de ce script"; exit 1; fi

titre "Installation de TOUS les outils non payants (ça peut prendre un moment)"
dest_arg=""
if [ -n "$dest" ]; then
  echo "  Les outils seront posés dans : $dest"
  dest_arg="--dest $dest"
fi
# Vigie installe tout le catalogue, outils payants écartés, et écrit un bilan.
(cd "$racine" && python3 -m vigie installer --tous --parallele 6 $dest_arg \
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
