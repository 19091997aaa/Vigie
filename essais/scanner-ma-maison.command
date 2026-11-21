#!/bin/bash
# Essai Vigie : ce que ton Mac et les appareils de ta maison montrent sur ton réseau.
#
# Double-clique sur ce fichier. Il ne modifie rien : il regarde seulement quelles
# « portes » (ports) répondent, comme le ferait un intrus branché sur ton Wi-Fi.
# Il ne scanne QUE ton réseau privé (192.168.x.x, 10.x.x.x, 172.16 à 31.x.x) et
# s'arrête tout seul sur un autre réseau (hôtel, travail, Wi-Fi public).
# Durée : 5 à 15 minutes selon le nombre d'appareils. Les résultats restent sur
# ton Mac, dans le dossier « resultats » à côté de ce fichier.
set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
ici="$(cd "$(dirname "$0")" && pwd)"
dossier="$ici/resultats"
mkdir -p "$dossier"

if ! command -v nmap >/dev/null; then
  echo "Nmap n'est pas installé. Demande à Claude de l'installer, puis relance."; exit 1
fi

ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
box=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')
case "$ip" in
  192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
  *) echo "Ce n'est pas un réseau privé de maison ($ip) : arrêt, rien n'a été scanné."; exit 1;;
esac
reseau="${ip%.*}.0/24"
echo "Ton Mac : $ip   Ta box : $box   Ton réseau : $reseau"
echo "{\"mac\": \"$ip\", \"box\": \"$box\", \"reseau\": \"$reseau\", \"date\": \"$(date '+%Y-%m-%d %H:%M')\"}" \
  > "$dossier/contexte.json"

echo; echo "1/3  Ton Mac : quelles portes il ouvre au réseau…"
nmap -sT -Pn -T4 --top-ports 1000 -sV --version-light -oX "$dossier/mac.xml" "$ip" >/dev/null

echo "2/3  Les appareils connectés à ta maison…"
nmap -sn -T4 -oX "$dossier/appareils.xml" "$reseau" >/dev/null
# Les appareils qui ne répondent pas au premier appel sont souvent dans la table du Mac.
arp -an | sed -n 's/.*(\([0-9.]*\)).*/\1/p' > "$dossier/arp.txt"
{ grep -o 'addr="[0-9.]*" addrtype="ipv4"' "$dossier/appareils.xml" | cut -d'"' -f2
  cat "$dossier/arp.txt"; } | grep -E "^${ip%.*}\.[0-9]+$" | grep -v -E "\.(0|255)$" \
  | grep -v "^$ip$" | sort -u -t. -k4,4n > "$dossier/liste.txt"
echo "     $(wc -l < "$dossier/liste.txt" | tr -d ' ') appareils trouvés (sans compter ton Mac)."

echo "3/3  Les portes ouvertes de chaque appareil (le plus long)…"
nmap -sT -Pn -T4 --top-ports 100 -sV --version-light -iL "$dossier/liste.txt" \
  -oX "$dossier/portes.xml" >/dev/null

echo; echo "Fini. Écris « c'est fait » à Claude : il traduit les résultats pour toi."
