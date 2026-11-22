#!/usr/bin/env bash
# Installateur Vigie pour Linux (Debian / Ubuntu / Kali).
# Double-clique dessus (ou : bash installer-linux.command).
# Il installe les outils du catalogue (sauf payants), puis prépare Vigie.
# Il ne touche à AUCUNE machine distante : il prépare seulement cette machine.
#
# Familles installées :
#   - OSINT passif (pseudos, mail, DNS, site) : sans action sur les cibles.
#   - Audit actif (ports, failles, TLS) : installés, mais Vigie ne les lance
#     qu'avec une autorisation signée (jamais tout seuls, jamais en gratuit).
# Les outils d'attaque lourde (Metasploit, Responder) et tout outil payant
# ou demandant un compte perso NE sont PAS posés ici : voir le bilan en fin.
set -u

racine="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
resume=()
titre() { printf "\n=== %s ===\n" "$1"; }
ok()    { printf "  [ok] %s\n" "$1"; resume+=("ok     : $1"); }
rate()  { printf "  [!]  %s\n" "$1"; resume+=("manque : $1"); }

# Un seul mot de passe sudo au début, gardé le temps de l'install.
if command -v sudo >/dev/null; then SUDO="sudo"; $SUDO -v || true; else SUDO=""; fi
APT=""; command -v apt-get >/dev/null && APT="apt-get"

# --- 0. Base système --------------------------------------------------------
titre "Base (Python, pipx, go, git, curl)"
if [ -n "$APT" ]; then
  $SUDO $APT update -y >/dev/null 2>&1
  $SUDO $APT install -y python3 python3-pip pipx golang-go git curl unzip jq >/dev/null 2>&1 \
    && ok "Paquets de base (python3, pipx, go, git, curl, jq)" \
    || rate "Paquets de base : vérifie ta connexion internet"
else
  rate "apt introuvable : ce script vise Debian/Ubuntu/Kali"
fi
python3 -m pipx ensurepath >/dev/null 2>&1 || true

# --- 1. Outils OSINT / audit en Python (pipx) -------------------------------
titre "Outils Python (OSINT passif + lecture)"
# dnstwist[full] : sans son module DNS il refuse de démarrer avec des résolveurs publics.
for p in sherlock-project "dnstwist[full]" checkdmarc maigret holehe theHarvester sqlmap; do
  c="${p%-project}"; c="${c%%\[*}"
  if python3 -m pipx install "$p" >/dev/null 2>&1; then ok "$p"
  else command -v "$c" >/dev/null && ok "$p (déjà là)" || rate "$p"; fi
done

# --- 2. Outils système (apt) ------------------------------------------------
titre "Outils système (apt)"
# Lecture / audit passif et actif. Attaque (nmap/hydra) : posés mais bridés par Vigie.
for paquet in exiftool dnsrecon whatweb nikto sslscan nmap lynis dnsutils nuclei naabu; do
  if [ -n "$APT" ] && $SUDO $APT install -y "$paquet" >/dev/null 2>&1; then ok "$paquet"
  else rate "$paquet (apt)"; fi
done

# --- 3. Outils Go (ProjectDiscovery + divers) -------------------------------
titre "Outils Go (reconnaissance)"
go_install() { # module  binaire
  if go install "$1" >/dev/null 2>&1; then ok "$2"
  else command -v "$2" >/dev/null && ok "$2 (déjà là)" || rate "$2 (go)"; fi
}
go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" subfinder
go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"           httpx
go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"             dnsx
go_install "github.com/lc/gau/v2/cmd/gau@latest"                          gau
go_install "github.com/sensepost/gowitness@latest"                        gowitness
go_install "github.com/owasp-amass/amass/v4/...@master"                   amass
go_install "github.com/gitleaks/gitleaks/v8@latest"                       gitleaks

# --- 4. Node (Lighthouse / pa11y / unlighthouse) ----------------------------
titre "Outils Node (qualité du site)"
if command -v npm >/dev/null || { [ -n "$APT" ] && $SUDO $APT install -y nodejs npm >/dev/null 2>&1; }; then
  for np in lighthouse pa11y @unlighthouse/cli; do
    if $SUDO npm install -g "$np" >/dev/null 2>&1; then ok "$np"; else rate "$np (npm)"; fi
  done
else
  rate "npm introuvable : Lighthouse / pa11y non posés"
fi

# --- 5. Vigie ---------------------------------------------------------------
titre "Vigie"
if [ -d "$racine/vigie" ]; then ok "Vigie présent dans $racine/vigie"
else rate "dossier vigie introuvable à côté de ce script"; fi

# --- 6. Vérification : Vigie voit-il les outils ? ---------------------------
titre "Vérification"
if [ -d "$racine/vigie" ]; then
  (cd "$racine" && python3 -m vigie outils 2>/dev/null | grep -iE "installé|branché" | head -30) || true
fi

# --- 7. Bilan ---------------------------------------------------------------
titre "Bilan"
for l in "${resume[@]}"; do echo "  $l"; done
cat <<'TXT'

NON installés ici (à faire à part) :
  - Payants (Shodan/uncover, Robin dark web...) : écartés volontairement.
  - Compte perso requis (GHunt/Google, Toutatis/Instaloader/Instagram, Snyk) : à lancer par toi.
  - Attaque lourde (Metasploit, Responder) : seulement sur serveur d'entraînement dédié.
  - Windows (HardeningKitty, AD...) : à poser sur une machine Windows.

Pour lancer Vigie (interface web dans le navigateur) :
  python3 -m vigie interface

Les outils d'audit actif (nmap, nuclei, naabu, sslscan) sont posés mais Vigie
ne les lance QU'AVEC une autorisation signée. Rien ne part tout seul.
TXT
