# Comparaisons d'outils, point par point — pavillon-noir.tech, 21/11/2026

Question d'Anass : « un outil dit-il quelque chose que l'autre oublie ? ». Pas seulement
« lequel trouve le plus » : on compare le **contenu**, élément par élément.

## Mail : Vigie (`mail`) contre checkdmarc

| Point | Vigie | checkdmarc |
| --- | --- | --- |
| SPF strict (-all) | oui | oui |
| DMARC en quarantaine | oui (correct) | oui (était « important » : aligné sur « à savoir ») |
| Pas d'adresse de rapport DMARC (rua) | oui | oui (avertissement) |
| Signature DKIM | **seul à chercher** | non |
| MTA-STS, rapports TLS | non | **seul** |
| DNSSEC | non | **seul** (activé) |
| SPF d'OVH avec « ptr » (déconseillé) | non | **seul** — oublié du rapport jusqu'ici, ajouté |
| Option DMARC « pct » abandonnée | non | **seul** — oublié du rapport jusqu'ici, ajouté |

## Site : Vigie (`site`) contre Lighthouse contre httpx contre SSLyze

| Point | Vigie | Lighthouse | httpx | SSLyze |
| --- | --- | --- | --- | --- |
| HSTS, CSP, protection du cadre absents | oui | oui | — | — |
| Isolation des fenêtres (COOP) absente | non | **seul** | — | — |
| X-Content-Type-Options absent | **seul** | non | — | — |
| Version visible (PHP 8.3) | oui (en-tête) | non | oui | — |
| WordPress, MySQL | non | non | **seul** | — |
| Certificat valide | oui | — | — | oui |
| TLS 1.3 absent, vieilles versions refusées | non | — | — | **seul** |

Piège Lighthouse : ses contrôles de protection affichent « réussi » même quand elles
manquent ; le verdict est dans le détail.

## Adresses annexes : Subfinder, Amass, theHarvester, crt.sh (vérifié à la main)

| Adresse | Subfinder | Amass | theHarvester | crt.sh direct |
| --- | --- | --- | --- | --- |
| www.pavillon-noir.tech | **oui** | non | non | non (seulement le domaine) |

Subfinder est le seul à trouver www (autre source que crt.sh). www pointe directement
vers le serveur (pas d'alias) : pas de risque de détournement (dnsx confirme).
Note : le certificat actuel (valable jusqu'au 09/02/2027) n'apparaît pas encore dans crt.sh.

## Pseudo « vigie » : Sherlock contre Maigret

Sherlock 80 comptes, Maigret 68, **40 en commun**. Seulement Sherlock : 40 sites (Docker
Hub, Mastodon, Gravatar, WordPress…). Seulement Maigret : 28 sites (Facebook, Twitter,
Twitch, Spotify, Stack Overflow…). Ils se complètent : chacun rate environ un tiers de
ce que voit l'autre. « vigie » est un mot courant : la plupart des comptes sont des homonymes.
**Trouvé au passage : Sherlock interroge HudsonRock, une base de mots de passe volés.**
Interdit hors offre payante : écarté dans le module `pseudos`.

## Métadonnées : ExifTool contre Exiv2 (5 images du site)

Même conclusion : aucune information sensible (seulement l'orientation de l'image).
ExifTool lit les PNG et plus de champs ; Exiv2 ne lit rien sur 4 images sur 5.

## Archives : gau contre les archives interrogées à la main

Wayback Machine : 0 page (vérifié en direct). AlienVault OTX : 0 (vérifié). URLScan : 0.
**Common Crawl injoignable depuis le Mac** (connexion refusée, aussi en direct) : gau ne
le signale pas, il rend « 0 ». Le résultat « aucune page archivée » repose donc sur 3
sources sur 4.

## DNS : dnsrecon contre mail/checkdmarc

Correction de la conclusion du lot 2 : dnsrecon voit **en plus** les réglages SRV de la
messagerie (IMAP, envoi, configuration automatique chez OVH) et l'adresse IPv6. Ce ne
sont pas des failles, mais de l'information que les autres ne montrent pas.
