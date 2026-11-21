#!/bin/bash
# Installateur Vigie pour Mac.
# Double-clique sur ce fichier (ou : bash installer-mac.command).
# Il installe les outils passifs et de scan, puis prépare Vigie.
# Il ne touche à aucune machine distante : il prépare seulement ton Mac.
set -u
racine="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/bin:$PATH"
resume=()
titre() { printf "\n=== %s ===\n" "$1"; }
ok()    { printf "  [ok] %s\n" "$1"; resume+=("ok   : $1"); }
rate()  { printf "  [!]  %s\n" "$1"; resume+=("manque : $1"); }

titre "Python"
if command -v python3 >/dev/null; then ok "Python présent : $(python3 --version)"
else rate "Installe Python depuis https://www.python.org/downloads/ puis relance"; exit 1; fi
python3 -m pip install --user --upgrade pip pipx >/dev/null 2>&1
python3 -m pipx ensurepath >/dev/null 2>&1

titre "Outils passifs (sans action sur les machines)"
# dnstwist[full] : sans son module DNS, dnstwist refuse de démarrer avec des résolveurs publics.
for p in sherlock-project "dnstwist[full]" checkdmarc; do
  c="${p%-project}"; c="${c%%\[*}"
  if python3 -m pipx install "$p" >/dev/null 2>&1; then ok "$p"; else
    command -v "$c" >/dev/null && ok "$p (déjà là)" || rate "$p"; fi
done

titre "Outils de scan (sur autorisation signée seulement)"
mkdir -p "$HOME/.local/bin"
arch=$(uname -m); case "$arch" in arm64) a=arm64;; x86_64) a=amd64;; *) a=amd64;; esac
for repo in projectdiscovery/subfinder projectdiscovery/httpx projectdiscovery/nuclei; do
  name=$(basename "$repo")
  url=$(curl -s "https://api.github.com/repos/$repo/releases/latest" \
        | grep -o "https://[^\"]*macOS_${a}\.zip\|https://[^\"]*darwin_${a}\.zip" | head -1)
  if [ -n "$url" ] && curl -sL "$url" -o "/tmp/$name.zip" \
     && unzip -oq "/tmp/$name.zip" -d "/tmp/$name" \
     && cp "/tmp/$name/$name" "$HOME/.local/bin/" 2>/dev/null; then ok "$name"
  else rate "$name : télécharge-le depuis https://github.com/$repo/releases"; fi
done

titre "Vigie"
if [ -f "$racine/vigie.zip" ]; then unzip -oq "$racine/vigie.zip" -d "$racine" && ok "Vigie décompressé"
elif [ -d "$racine/vigie" ]; then ok "Vigie déjà présent"
else rate "vigie.zip introuvable : mets-le dans le même dossier que ce script"; fi

titre "Vérification : Vigie appelle-t-il les outils ?"
if [ -d "$racine/vigie" ]; then (cd "$racine/vigie" && python3 -m vigie outils 2>/dev/null | grep -E "installé" | head); fi

titre "Bilan"
for l in "${resume[@]}"; do echo "  $l"; done
cat <<'TXT'

Outils d'attaque (Nmap, Metasploit, sqlmap, Hydra, Responder) : à installer à la main,
et à n'utiliser qu'avec une autorisation signée. Jamais lancés tout seuls.

Pour lancer Vigie :
  cd vigie
  python3 -m vigie interface

Rouvre ton terminal avant le premier lancement.
TXT
