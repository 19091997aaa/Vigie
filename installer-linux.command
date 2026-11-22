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

# Si un dossier cible est donné, TOUT doit y aller (y compris les caches), sinon le
# disque système se remplit. On vérifie d'abord que ce dossier est bien sur un disque
# séparé : sinon on s'arrête, car la personne a oublié de monter le disque dédié.
if [ -n "$dest" ]; then
  titre "Disque cible : $dest"
  $SUDO mkdir -p "$dest" 2>/dev/null && $SUDO chown -R "$USER":"$USER" "$dest" 2>/dev/null || true
  cible_fs="$(df -P "$dest" 2>/dev/null | awk 'NR==2{print $6}')"
  racine_fs="$(df -P / 2>/dev/null | awk 'NR==2{print $6}')"
  libre_go="$(df -PBG "$dest" 2>/dev/null | awk 'NR==2{gsub("G","",$4); print $4}')"
  if [ -z "$cible_fs" ] || [ "$cible_fs" = "$racine_fs" ]; then
    echo "  [STOP] $dest est sur le disque SYSTÈME (/), pas sur un disque séparé."
    echo "         Le disque de 50 Go n'est pas monté. Monte-le d'abord :"
    echo "           sudo mkfs.ext4 /dev/sdc   (⚠ efface le disque — vérifie 'lsblk')"
    echo "           sudo mkdir -p $dest && sudo mount /dev/sdc $dest"
    echo "           sudo chown -R \$USER:\$USER $dest"
    echo "         Puis relance ce script. (J'arrête pour ne pas remplir le système.)"
    exit 1
  fi
  echo "  [ok] $dest est sur un disque séparé (${libre_go:-?} Go libres)"
  # Les caches de compilation (Go surtout) iront aussi sur ce disque.
  export GOCACHE="$dest/cache/go-build" GOMODCACHE="$dest/go/pkg/mod"
  export PIP_CACHE_DIR="$dest/cache/pip" TMPDIR="$dest/tmp"
  export GOPATH="$dest/go" GOBIN="$dest/bin"
  mkdir -p "$GOCACHE" "$PIP_CACHE_DIR" "$TMPDIR" "$dest/go" "$dest/bin" 2>/dev/null || true
fi

liberer_apt() {
  # Au démarrage, unattended-upgrades tient le verrou tout le temps de l'install, pas
  # seulement au début. On arrête (pour cette session) les mises à jour automatiques
  # afin de libérer apt durant tout le travail. Une VM de labo : sans risque.
  $SUDO systemctl stop unattended-upgrades.service apt-daily.service \
        apt-daily-upgrade.service >/dev/null 2>&1 || true
  $SUDO systemctl stop apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
}

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
liberer_apt
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
# L'install dure longtemps : sans ça, les droits « sudo » expirent au bout de ~15 min
# et les outils apt installés ensuite (nmap, clamav…) échouent. On garde sudo actif.
if [ -n "$SUDO" ]; then
  ( while true; do sudo -n true 2>/dev/null || exit; sleep 50; done ) &
  SUDO_KEEPALIVE=$!
  trap 'kill "$SUDO_KEEPALIVE" 2>/dev/null' EXIT
fi
dest_arg=""
if [ -n "$dest" ]; then
  echo "  Les outils seront posés dans : $dest"
  dest_arg="--dest $dest"
fi
# Vigie installe tout le catalogue, outils payants écartés, et écrit un bilan.
# Si une install précédente existe, on ne réessaie QUE ce qui avait échoué (rapide).
reprise_arg=""
if [ -f "$HOME/vigie-installation.json" ]; then
  reprise_arg="--reprendre $HOME/vigie-installation.json"
  echo "  (relance ciblée : seuls les outils encore manquants seront réessayés)"
fi
(cd "$racine" && python3 -m vigie installer --tous --parallele 6 $dest_arg $reprise_arg \
    --rapport "$HOME/vigie-installation.json")

titre "Nettoyage des caches de compilation (récupère de la place)"
# Le cache de compilation Go peut peser des dizaines de Go. Les OUTILS déjà posés
# (dans bin/, pipx/) n'en ont plus besoin : on le vide après coup. Rien d'installé
# n'est touché. On garde le cache des modules Go (petit, accélère un ré-essai).
avant="$(df -Pm "${dest:-$HOME}" 2>/dev/null | awk 'NR==2{print $4}')"
go clean -cache >/dev/null 2>&1 || rm -rf "${GOCACHE:-$HOME/.cache/go-build}" 2>/dev/null || true
rm -rf "${PIP_CACHE_DIR:-$HOME/.cache/pip}" 2>/dev/null || true
rm -rf "$HOME/.cache/go-build" "$HOME/.cache/pip" 2>/dev/null || true   # restes éventuels sur /
apres="$(df -Pm "${dest:-$HOME}" 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "$avant" ] && [ -n "$apres" ]; then
  echo "  [ok] $(( (apres - avant) / 1024 )) Go récupérés (place libre : $(( apres / 1024 )) Go)"
fi

titre "Vérification : ce que Vigie voit maintenant"
# Vigie regarde lui-même quels outils du catalogue sont sur la machine (y compris
# ceux posés à la main avec apt : clamav, yara, tcpdump…).
(cd "$racine" && python3 -m vigie registre 2>/dev/null | tail -1) || true
echo "  Le détail (outil par outil) : onglet « Lancer un outil » de l'interface."

cat <<'TXT'

Terminé. Le détail outil par outil est dans :  ~/vigie-installation.json

Pour lancer Vigie (dans le navigateur) :
  python3 -m vigie interface

Onglet « Lancer un outil » : chaque outil, un par un, sur une cible.
Les outils actifs/offensifs ne partent qu'avec une autorisation signée
(onglet « Outils manuels »).
TXT
