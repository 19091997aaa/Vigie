#!/usr/bin/env bash
# Libérer de la place sur le disque des outils de Vigie (Linux).
# Double-clique dessus, ou :  bash liberer-place.command [dossier des outils]
#
# Pourquoi (28/11/2026) : le disque « vigie-outils » de 50 Go de la VM s'est retrouvé
# plein. Ce script :
#   1. montre la place libre et ce qui prend le plus de place ;
#   2. vide ce qui ne sert plus (restes et caches de compilation Go / pip / uv / npm /
#      pipx, cache de construction Docker, images Docker sans nom) ;
#   3. propose (tu réponds o ou n) de retirer garak et Nebula, ~6 Go chacun.
# Il ne touche JAMAIS à un outil installé sans te demander, ni aux conteneurs ou aux
# données Docker (volumes) de tes outils.
set -u

dest="${1:-}"
if [ -z "$dest" ]; then
  if [ -d /opt/vigie-outils ]; then dest=/opt/vigie-outils
  else dest="$HOME/.local/share/vigie-outils"; fi
fi
titre() { printf "\n=== %s ===\n" "$1"; }
libre_mo() { df -Pm "$1" 2>/dev/null | awk 'NR==2{print $4}'; }
go_lisible() { awk -v m="${1:-0}" 'BEGIN{printf "%.1f Go", m/1024}'; }

titre "Place libre maintenant"
avant="$(libre_mo "$dest")"; avant_sys="$(libre_mo /)"
echo "  Disque des outils ($dest) : $(go_lisible "$avant") libres"
echo "  Disque du système (/)      : $(go_lisible "$avant_sys") libres"

titre "Ce qui prend le plus de place dans $dest"
if [ -d "$dest" ]; then
  du -xh --max-depth=2 "$dest" 2>/dev/null | sort -rh | head -15 | sed 's/^/  /'
else
  echo "  (dossier introuvable : $dest)"
fi

titre "Ménage sans risque (rien d'installé n'est touché)"
# Restes de compilation et caches de Vigie sur le disque des outils.
for d in "$dest/tmp" "$dest/cache"; do
  [ -d "$d" ] && find "$d" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
done
echo "  [ok] restes et caches de compilation (tmp, cache)"
# Cache des modules Go : utile seulement pour recompiler. Go le pose en lecture seule,
# d'où « go clean -modcache » (et rien d'autre).
if command -v go >/dev/null 2>&1; then
  GOPATH="$dest/go" GOMODCACHE="$dest/go/pkg/mod" go clean -modcache >/dev/null 2>&1 || true
  go clean -modcache >/dev/null 2>&1 || true
  go clean -cache >/dev/null 2>&1 || true
  echo "  [ok] caches de Go"
fi
# Caches pipx / pip / uv / npm (ils se refont tout seuls si besoin).
rm -rf "$dest/pipx/.cache" "$HOME/.cache/pip" "$HOME/.cache/uv" "$HOME/.cache/go-build" \
       "$HOME/.local/share/pipx/.cache" 2>/dev/null || true
if command -v npm >/dev/null 2>&1; then npm cache clean --force >/dev/null 2>&1 || true; fi
echo "  [ok] caches de pipx, pip, uv et npm"
# Docker : seulement le cache de construction et les images SANS nom (restes d'une
# construction ratée). Les images, conteneurs et volumes de tes outils restent.
docker_() {
  if docker info >/dev/null 2>&1; then docker "$@"
  elif command -v sg >/dev/null 2>&1 && id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
    sg docker -c "docker $*"
  else return 1; fi
}
if command -v docker >/dev/null 2>&1; then
  if docker_ builder prune -af >/dev/null 2>&1 && docker_ image prune -f >/dev/null 2>&1; then
    echo "  [ok] cache de construction Docker et images sans nom"
  else
    echo "  [--] Docker ne répond pas (arrêté ou sans droit) : rien fait de ce côté"
  fi
fi

titre "Les deux plus gros outils : garak et Nebula (~6 Go chacun)"
echo "  Ce sont des outils pour tester des IA : ils ne servent pas au diagnostic."
echo "  L'installeur pourra les remettre plus tard, s'il y a assez de place."
pipx_() { PIPX_HOME="$dest/pipx" PIPX_BIN_DIR="$dest/bin" pipx "$@"; }
for outil in garak nebula-ai nebula; do
  if [ -d "$dest/pipx/venvs/$outil" ]; then
    taille="$(du -sh "$dest/pipx/venvs/$outil" 2>/dev/null | cut -f1)"
    read -r -p "  Retirer $outil ($taille) ? Tape o pour oui, n pour non : " rep
    if [ "$rep" = "o" ] || [ "$rep" = "O" ]; then
      pipx_ uninstall "$outil" >/dev/null 2>&1 || rm -rf "$dest/pipx/venvs/$outil"
      echo "  [ok] $outil retiré"
    else
      echo "  [--] $outil gardé"
    fi
  fi
done

titre "Résultat"
apres="$(libre_mo "$dest")"; apres_sys="$(libre_mo /)"
if [ -n "$avant" ] && [ -n "$apres" ]; then
  echo "  Disque des outils : $(go_lisible "$apres") libres ($(go_lisible $((apres - avant))) récupérés)"
fi
if [ -n "$avant_sys" ] && [ -n "$apres_sys" ]; then
  echo "  Disque du système : $(go_lisible "$apres_sys") libres ($(go_lisible $((apres_sys - avant_sys))) récupérés)"
fi
echo
echo "  Prends une photo de cette fenêtre et envoie-la, pour voir ce qui prenait la place."
read -r -p "  Appuie sur Entrée pour fermer. " _
