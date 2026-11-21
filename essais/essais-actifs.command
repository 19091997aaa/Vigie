#!/bin/bash
# Essais Vigie : les outils d'audit ACTIFS, sur deux cibles publiques faites pour ça.
#
#   - scanme.nmap.org      : machine mise à disposition par le projet Nmap, qui
#                            AUTORISE les scans de ports (sans le marteler) ;
#   - testphp.vulnweb.com  : faux site troué publié par Acunetix POUR tester les
#                            outils d'analyse de sites.
# Aucun outil d'attaque (sqlmap, hydra...) n'est lancé ici : seulement des outils
# d'audit, à vitesse réduite. Rien d'autre n'est visé.
# Double-clique sur ce fichier. Durée : 20 à 40 minutes. Les résultats restent sur ton
# Mac, dans essais/resultats/actifs. Ensuite, écris « c'est fait » à Claude.
set -u
export PATH="/opt/homebrew/bin:$HOME/.local/bin:$HOME/go/bin:/usr/local/bin:$PATH"
ici="$(cd "$(dirname "$0")" && pwd)"
sortie="$ici/resultats/actifs"
mkdir -p "$sortie"
PORTS="scanme.nmap.org"
SITE="testphp.vulnweb.com"

etape() { printf "\n=== %s ===\n" "$1"; }
installe() {  # installe un outil absent (Homebrew, sinon pipx)
  command -v "$1" >/dev/null && return
  echo "  installation de $1…"; brew install "$2" >/dev/null 2>&1 || pipx install "$2" >/dev/null 2>&1
}
for paire in "nmap nmap" "naabu naabu" "rustscan rustscan" "sslscan sslscan" "nuclei nuclei" \
             "nikto nikto" "ffuf ffuf" "katana katana" "wapiti wapiti3" "arjun arjun"; do
  set -- $paire; installe "$1" "$2"
done

etape "1/10 Nmap : ports de $PORTS"
nmap -sT -Pn -T3 --top-ports 1000 -sV --version-light -oX "$sortie/nmap.xml" "$PORTS" >/dev/null 2>&1
etape "2/10 Nmap + vulners : failles connues des services de $PORTS"
nmap -sT -Pn -T3 --top-ports 100 -sV --script vulners -oX "$sortie/nmap-vulners.xml" "$PORTS" >/dev/null 2>&1
etape "3/10 Naabu : ports de $PORTS"
naabu -host "$PORTS" -top-ports 1000 -scan-type c -rate 100 -silent -json -o "$sortie/naabu.jsonl" >/dev/null 2>&1
etape "4/10 RustScan : ports de $PORTS"
rustscan -a "$PORTS" --top -b 200 -t 2000 --ulimit 2000 -g > "$sortie/rustscan.txt" 2>/dev/null
etape "5/10 sslscan : chiffrement de $SITE"
sslscan --no-colour "$SITE" > "$sortie/sslscan.txt" 2>&1
etape "6/10 Nuclei : failles connues de $SITE"
nuclei -u "http://$SITE" -rate-limit 20 -jsonl -silent -o "$sortie/nuclei.jsonl" >/dev/null 2>&1
etape "7/10 Nikto : $SITE"
nikto -h "http://$SITE" -maxtime 900s -Format json -o "$sortie/nikto.json" >/dev/null 2>&1
etape "8/10 Wapiti : $SITE"
wapiti -u "http://$SITE/" --max-scan-time 900 -f json -o "$sortie/wapiti.json" >/dev/null 2>&1
etape "9/10 Katana et Arjun : pages et paramètres de $SITE"
katana -u "http://$SITE" -d 2 -rate-limit 10 -silent -o "$sortie/katana.txt" >/dev/null 2>&1
arjun -u "http://$SITE/listproducts.php" -oJ "$sortie/arjun.json" -q >/dev/null 2>&1
etape "10/10 ffuf : fichiers et dossiers cachés de $SITE (petite liste)"
liste="$sortie/liste.txt"
printf "%s\n" admin administrator login backup backups old test tmp uploads upload images \
  includes include config conf cgi-bin CVS .git .env .htaccess phpinfo.php info.php \
  robots.txt sitemap.xml crossdomain.xml index.bak db database sql dump.sql secret private \
  hidden pictures AJAX Flash Templates Mod_Rewrite_Shop secured > "$liste"
ffuf -u "http://$SITE/FUZZ" -w "$liste" -rate 10 -mc 200,204,301,302,307,401,403 \
  -of json -o "$sortie/ffuf.json" -s >/dev/null 2>&1

echo; echo "Fini. Écris « c'est fait » à Claude : il compare les résultats pour toi."
