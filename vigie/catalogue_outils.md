# Catalogue des outils de Vigie

222 outils (labs d'entraînement exclus). Relevé du document du 20/11/2026.
Colonne « besoin » : ce qu'il faut en plus de l'outil lui-même pour qu'il tourne.

## OSINT : pseudos, e-mails, images, métadonnées (23)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| Sherlock | rien | Cherche un pseudo sur des centaines de réseaux sociaux. | https://github.com/sherlock-project/sherlock |
| Maigret | rien | Comme Sherlock, mais fabrique en plus un dossier à partir des profils trouvés. | https://github.com/soxoj/maigret |
| ArchiveBox | rien | Archive des pages web pour garder une preuve d'une page qui peut disparaître. | https://github.com/ArchiveBox/ArchiveBox |
| SpiderFoot | rien | Automatise la collecte d'infos sur un domaine, une IP, un e-mail ou un nom. | https://github.com/smicallef/spiderfoot |
| Social Analyzer | rien | Analyse un pseudo sur des centaines de sites, avec une note de fiabilité. | https://github.com/qeeqbox/social-analyzer |
| GHunt | rien | Récupère les infos publiques d'un compte Google à partir d'un e-mail. (données personnelles) | https://github.com/mxrch/GHunt |
| PhoneInfoga | rien | Infos publiques sur un numéro de téléphone (pays, opérateur, traces en ligne). (données personnelles) | https://github.com/sundowndev/phoneinfoga |
| theHarvester | rien | Collecte e-mails, sous-domaines et noms d'une société à partir de sources publiques. | https://github.com/laramies/theHarvester |
| Holehe | rien | Teste si une adresse e-mail a un compte sur 120+ sites. | https://github.com/megadose/holehe |
| Instaloader | rien | Télécharge des photos et métadonnées publiques d'Instagram. | https://github.com/instaloader/instaloader |
| Recon-ng | rien | Cadre de reconnaissance web en ligne de commande, avec des modules. | https://github.com/lanmaster53/recon-ng |
| ExifTool | rien | Lit et modifie les métadonnées (photo, PDF, Office) : GPS, appareil, auteur. | https://github.com/exiftool/exiftool |
| Toutatis | rien | Infos publiques d'un compte Instagram. | https://github.com/megadose/toutatis |
| Exiv2 | rien | Lit les métadonnées d'images en ligne de commande ou via bibliothèque. | https://github.com/exiv2/exiv2 |
| auto-archiver | rien | Archive automatiquement des liens et médias (outil de Bellingcat). | https://github.com/bellingcat/auto-archiver |
| Datashare | rien | Cherche dans de gros volumes de documents (outil des journalistes d'investigation). | https://github.com/ICIJ/datashare |
| Metagoofil | rien | Récupère les documents publics d'un site et en extrait les métadonnées. | https://github.com/opsdisk/metagoofil |
| InVID-WeVerify | rien | Extension de navigateur pour vérifier images et vidéos (recherche inversée, loupe, métadonnées). (extension navigateur) | https://github.com/AFP-Medialab/verification-plugin |
| Flowsint | rien | Plateforme graphique pour relier les résultats d'une enquête OSINT. | https://github.com/reconurge/flowsint |
| Robin | jetons payants ou modèle local | Recherche sur le dark web assistée par LLM (clé API ou modèle local nécessaire). | https://github.com/apurvsinghgautam/robin |
| geo-sleuth | rien | Aide à trouver où une photo a été prise (carte, relief, ombres). | https://github.com/Oldcircle/geo-sleuth |
| user-scanner | rien | Recherche pseudo et e-mail en un seul outil, avec support MCP. | https://github.com/kaifcodec/user-scanner |
| OpenOSINT | rien | Agent OSINT qui pilote 21 outils publics par questions en langage naturel. | https://github.com/OpenOSINT/OpenOSINT |

## OSINT : ma société est-elle bien référencée ? (24)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| Web-Check | rien | Tableau de bord qui analyse un site (DNS, TLS, en-têtes, redirections, ports, SEO de base). (auto-hébergeable) | https://github.com/Lissy93/web-check |
| Gitleaks | rien | Détecte les secrets dans l'historique Git. | https://github.com/gitleaks/gitleaks |
| Lighthouse | rien | Audit de page : performance, SEO, accessibilité, bonnes pratiques. (SEO) | https://github.com/GoogleChrome/lighthouse |
| TruffleHog | rien | Cherche des mots de passe et clés oubliés dans du code et des dépôts. | https://github.com/trufflesecurity/trufflehog |
| OWASP Amass | rien | Cartographie la surface exposée d'une organisation (domaines, DNS, réseaux). | https://github.com/owasp-amass/amass |
| Subfinder | rien | Liste les sous-domaines d'un domaine à partir de sources publiques. | https://github.com/projectdiscovery/subfinder |
| httpx | rien | Vérifie quels sites répondent et récupère leur titre, technologie et statut. | https://github.com/projectdiscovery/httpx |
| WhatWeb | rien | Identifie les technologies d'un site (CMS, serveur, bibliothèques). | https://github.com/urbanadventurer/WhatWeb |
| dnstwist | rien | Détecte les noms de domaine ressemblants au tien (typosquatting, hameçonnage). | https://github.com/elceef/dnstwist |
| sitespeed.io | rien | Mesure la vitesse réelle d'un site (impact sur le référencement). (SEO) | https://github.com/sitespeedio/sitespeed.io |
| Unlighthouse | rien | Lance Lighthouse sur tout un site pour trouver les pages faibles en SEO et performance. (SEO) | https://github.com/harlan-zw/unlighthouse |
| Pa11y | rien | Teste l'accessibilité d'un site (critère aussi pris en compte par les moteurs). (SEO) | https://github.com/pa11y/pa11y |
| gowitness | rien | Captures d'écran de sites web en masse. | https://github.com/sensepost/gowitness |
| SSLyze | rien | Analyse rapide de la configuration TLS d'un site. | https://github.com/nabla-c0d3/sslyze |
| uncover | clé API (souvent gratuite) | Interroge Shodan, Censys et autres moteurs pour voir ce qui est exposé (clés API gratuites). | https://github.com/projectdiscovery/uncover |
| dnsrecon | rien | Audit DNS : enregistrements, transferts de zone, sous-domaines. | https://github.com/darkoperator/dnsrecon |
| dnsx | rien | Interroge le DNS en masse (enregistrements A, MX, TXT…). | https://github.com/projectdiscovery/dnsx |
| cloud_enum | rien | Cherche des ressources cloud publiques (Azure, AWS, GCP) au nom d'une marque. | https://github.com/initstring/cloud_enum |
| LinkChecker | rien | Trouve les liens cassés d'un site (mauvais pour le SEO). (SEO) | https://github.com/linkchecker/linkchecker |
| checkdmarc | rien | Vérifie SPF, DKIM et DMARC d'un domaine (réputation des e-mails). | https://github.com/domainaware/checkdmarc |
| EyeWitness | rien | Prend des captures d'écran de sites et services exposés pour les passer en revue. | https://github.com/ChrisTruncer/EyeWitness |
| Betterleaks | rien | Cherche les secrets qui ont fuité (clés, jetons) dans le code. | https://github.com/betterleaks/betterleaks |
| Xingrin | rien | Plateforme de gestion de surface d’attaque et d’automatisation de scans autorisés. | https://github.com/yyhuni/xingrin |
| ARL-Next | rien | Surveillance continue de la surface d'attaque et des actifs d'une société (documentation en chinois). | https://github.com/owl234/ARL-Next |

## Reconnaissance et scan réseau (16)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| Masscan | rien | Scanner de ports ultra-rapide pour de très grandes plages d'adresses. | https://github.com/robertdavidgraham/masscan |
| RustScan | rien | Scanner de ports très rapide qui passe ensuite la main à Nmap. | https://github.com/bee-san/RustScan |
| Bettercap | rien | Outil d'analyse et d'audit réseau local (écoute, ARP, Wi-Fi, Bluetooth). Légal seulement sur ton réseau. | https://github.com/bettercap/bettercap |
| Nmap | rien | Le scanner de ports et de services de référence. (licence Nmap (NPSL), gratuite) | https://github.com/nmap/nmap |
| reconftw | rien | Enchaîne une quarantaine d'outils de reconnaissance sur un domaine. | https://github.com/six2dez/reconftw |
| Osmedeus | rien | Plateforme de reconnaissance et de scan de vulnérabilités automatisés. | https://github.com/j3ssie/osmedeus |
| ZMap | rien | Scanne tout Internet sur un port en quelques minutes (recherche, réseaux entiers). | https://github.com/zmap/zmap |
| Naabu | rien | Scan de ports rapide et simple, facile à enchaîner avec d'autres outils. | https://github.com/projectdiscovery/naabu |
| AutoRecon | rien | Lance automatiquement une série de scans pour chaque machine. Très pratique en CTF et labs. | https://github.com/AutoRecon/AutoRecon |
| OWASP Nettacker | rien | Automatise scan de ports, détection de services et tests de vulnérabilités. | https://github.com/OWASP/Nettacker |
| Angry IP Scanner | rien | Scanner d'adresses IP et de ports avec interface graphique, très simple. | https://github.com/angryip/ipscan |
| IVRE | clé API (souvent gratuite) | Base de reconnaissance réseau auto-hébergée, façon petit Shodan perso. | https://github.com/ivre/ivre |
| nmap-vulners | rien | Script Nmap qui affiche les failles connues des versions détectées. | https://github.com/vulnersCom/nmap-vulners |
| arp-scan | rien | Liste les machines d'un réseau local par ARP. | https://github.com/royhills/arp-scan |
| tlsx | rien | Récupère les certificats TLS d'une liste de machines. | https://github.com/projectdiscovery/tlsx |
| Nerva | rien | Identifie vite le service derrière chaque port (170+ protocoles TCP/UDP/SCTP). | https://github.com/praetorian-inc/nerva |

## Scan de vulnérabilités et audit de configuration (29)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| Trivy | rien | Scanne conteneurs, dépôts et fichiers d'infra (Terraform, Kubernetes) pour trouver failles et erreurs de config. | https://github.com/aquasecurity/trivy |
| Nuclei | rien | Scanner de vulnérabilités à base de modèles YAML, avec une énorme communauté. | https://github.com/projectdiscovery/nuclei |
| PEASS-ng (WinPEAS/LinPEAS) | rien | Cherche les mauvaises configurations qui permettent de devenir administrateur sur Windows et Linux. | https://github.com/peass-ng/PEASS-ng |
| Semgrep | rien | Analyse de code source pour trouver des failles (édition communautaire en ligne de commande). (règles tierces sous licences variées) | https://github.com/semgrep/semgrep |
| Lynis | rien | Audit de sécurité et de durcissement d'un serveur Linux, avec conseils. | https://github.com/CISOfy/lynis |
| Prowler | rien | Audit de sécurité cloud : Azure, Microsoft 365, AWS, Google Cloud. | https://github.com/prowler-cloud/prowler |
| Nuclei Templates | rien | Les modèles de détection communautaires de Nuclei. (données) | https://github.com/projectdiscovery/nuclei-templates |
| Grype | rien | Cherche les vulnérabilités connues dans images et paquets. | https://github.com/anchore/grype |
| Kubescape | rien | Audit de sécurité Kubernetes (conformité, mauvaises configurations). | https://github.com/kubescape/kubescape |
| Syft | rien | Fait l'inventaire des composants logiciels (SBOM). | https://github.com/anchore/syft |
| Checkov | rien | Analyse Terraform, Bicep, ARM, etc. pour repérer les erreurs de sécurité avant déploiement. | https://github.com/bridgecrewio/checkov |
| kube-bench | rien | Vérifie un cluster Kubernetes contre le référentiel CIS. | https://github.com/aquasecurity/kube-bench |
| ScoutSuite | rien | Audit de config cloud multi-fournisseur (dont Azure). | https://github.com/nccgroup/ScoutSuite |
| OWASP Dependency-Check | rien | Détecte les bibliothèques vulnérables dans un projet. | https://github.com/dependency-check/DependencyCheck |
| OpenVAS (Greenbone Community) | rien | Scanner de vulnérabilités réseau complet, édition communautaire libre. | https://github.com/greenbone/openvas-scanner |
| PrivescCheck | rien | Audit Windows des erreurs de config qui mènent à l'élévation de privilèges. | https://github.com/itm4n/PrivescCheck |
| linux-smart-enumeration | rien | Énumération Linux pas à pas, plus lisible que LinPEAS pour débuter. | https://github.com/diego-treitos/linux-smart-enumeration |
| ComplianceAsCode | rien | Profils de sécurité (CIS, ANSSI) utilisables avec OpenSCAP. (données) | https://github.com/ComplianceAsCode/content |
| ScubaGear | rien | Compare ta config Microsoft 365 aux recommandations de l'agence américaine CISA. | https://github.com/cisagov/ScubaGear |
| ROADtools | rien | Explore et audite un tenant Entra ID (Azure AD). | https://github.com/dirkjanm/ROADtools |
| MicroBurst | rien | Scripts d'audit et de test d'intrusion pour Azure. | https://github.com/NetSPI/MicroBurst |
| Microsoft365DSC | rien | Décrit et contrôle la config Microsoft 365 sous forme de code. | https://github.com/Microsoft365DSC/Microsoft365DSC |
| HardeningKitty | rien | Audite la config de sécurité de Windows par rapport aux référentiels (CIS, Microsoft). | https://github.com/scipag/HardeningKitty |
| OpenSCAP | rien | Vérifie la conformité d'un système Linux à une norme (CIS, ANSSI…). | https://github.com/OpenSCAP/openscap |
| AADInternals | rien | Boîte à outils PowerShell pour administrer et auditer Entra ID / Microsoft 365. | https://github.com/Gerenios/AADInternals |
| Monkey365 | rien | Audit de sécurité Microsoft 365, Entra ID et Azure en PowerShell. | https://github.com/silverhack/monkey365 |
| Maester | rien | Tests de sécurité automatisés pour Microsoft 365 et Entra ID. | https://github.com/maester365/maester |
| AzureHound | rien | Collecte les relations d'accès Entra ID/Azure pour BloodHound. | https://github.com/SpecterOps/AzureHound |
| PSRule for Azure | rien | Contrôle les ressources et modèles Azure par rapport aux bonnes pratiques Microsoft. (utile AZ-104) | https://github.com/Azure/PSRule.Rules.Azure |

## Pentest web (25)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| mitmproxy | rien | Proxy pour voir et modifier le trafic HTTP/HTTPS (analyse d'apps). | https://github.com/mitmproxy/mitmproxy |
| Metasploit Framework | rien | Le grand cadre de test d'intrusion : modules d'exploitation et d'analyse. | https://github.com/rapid7/metasploit-framework |
| sqlmap | rien | Détecte et teste automatiquement les injections SQL. | https://github.com/sqlmapproject/sqlmap |
| Katana | rien | Explore (crawl) un site pour lister ses pages et ses points d'entrée. | https://github.com/projectdiscovery/katana |
| ffuf | rien | Cherche pages et paramètres cachés d'un site par force brute de listes. | https://github.com/ffuf/ffuf |
| OWASP ZAP | rien | Scanner et proxy de test d'applications web, gratuit, idéal pour débuter. | https://github.com/zaproxy/zaproxy |
| XSStrike | rien | Détecteur de XSS avancé. | https://github.com/s0md3v/XSStrike |
| dirsearch | rien | Cherche des répertoires et fichiers cachés sur un serveur web. | https://github.com/maurosoria/dirsearch |
| Gobuster | rien | Cherche dossiers, fichiers, sous-domaines par listes de mots. | https://github.com/OJ/gobuster |
| Nikto | rien | Scanner web classique : configurations dangereuses, fichiers sensibles, versions anciennes. | https://github.com/sullo/nikto |
| feroxbuster | rien | Découverte rapide de contenus web cachés, récursive. | https://github.com/epi052/feroxbuster |
| jwt_tool | rien | Teste la sécurité des jetons JWT. | https://github.com/ticarpi/jwt_tool |
| Wfuzz | rien | Teste des paramètres web en y injectant des listes de valeurs. | https://github.com/xmendez/wfuzz |
| Arjun | rien | Trouve les paramètres HTTP cachés d'une page. | https://github.com/s0md3v/Arjun |
| Commix | rien | Teste les injections de commandes sur les applications web. | https://github.com/commixproject/commix |
| Dalfox | rien | Scanner de failles XSS rapide. | https://github.com/hahwul/dalfox |
| gau | rien | Récupère les anciennes URL d'un domaine depuis les archives web. | https://github.com/lc/gau |
| Interactsh | rien | Détecte les failles « aveugles » (SSRF, injections) par retour de connexion. | https://github.com/projectdiscovery/interactsh |
| Retire.js | rien | Repère les bibliothèques JavaScript vulnérables. | https://github.com/RetireJS/retire.js |
| Exploit-DB (searchsploit) | rien | Copie hors ligne de la base d’exploits publics, avec recherche en ligne de commande. (sur GitLab, pas GitHub) | https://gitlab.com/exploit-database/exploitdb |
| Burp Suite Community | rien | Proxy d’interception pour tester des sites web à la main. Gratuit mais PAS open source, et sans scanner automatique. (édition Community gratuite) | https://portswigger.net/burp/communitydownload |
| SSRFmap | rien | Teste les failles SSRF (le serveur fait des requêtes à la place de l'attaquant). | https://github.com/swisskyrepo/SSRFmap |
| sslscan | rien | Liste les protocoles et chiffrements TLS acceptés par un serveur. | https://github.com/rbsec/sslscan |
| Wapiti | rien | Scanner web « boîte noire » (XSS, injections, fichiers). | https://github.com/wapiti-scanner/wapiti |
| WPProbe | rien | Liste rapide des extensions WordPress d'un site et de leurs failles connues. (alternative libre à WPScan) | https://github.com/Chocapikk/wpprobe |

## Active Directory (14)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| Impacket | rien | Bibliothèque et scripts pour parler aux protocoles Windows (SMB, Kerberos…). | https://github.com/fortra/impacket |
| Responder | rien | Montre si un réseau Windows laisse fuiter des identifiants (LLMNR, NBT-NS). | https://github.com/lgandx/Responder |
| NetExec | rien | Teste les accès SMB, WinRM, LDAP… sur un réseau Windows (suite de CrackMapExec). | https://github.com/Pennyw0rth/NetExec |
| Certipy | rien | Audite les services de certificats Active Directory (AD CS). | https://github.com/ly4k/Certipy |
| BloodHound | rien | Dessine les chemins d'attaque dans Active Directory pour les corriger. | https://github.com/SpecterOps/BloodHound |
| kerbrute | rien | Teste des comptes et mots de passe via Kerberos. | https://github.com/ropnop/kerbrute |
| Adalanche | rien | Visualise et audite les droits dans Active Directory, utile côté défense. | https://github.com/lkarlslund/Adalanche |
| SMBMap | rien | Liste les partages SMB et les droits dessus. | https://github.com/ShawnDEvans/smbmap |
| mitm6 | rien | Teste l'attaque via IPv6 contre un domaine Windows. | https://github.com/dirkjanm/mitm6 |
| enum4linux-ng | rien | Énumère les infos d'un serveur Windows/Samba (utilisateurs, partages). | https://github.com/cddmp/enum4linux-ng |
| Locksmith | rien | Trouve et corrige les failles de configuration AD CS (côté défense). | https://github.com/jakehildreth/Locksmith |
| ldapdomaindump | rien | Exporte les infos d'un domaine via LDAP en pages lisibles. | https://github.com/dirkjanm/ldapdomaindump |
| DPAT | rien | Audit des mots de passe d'un domaine à partir des hashs, avec rapport. | https://github.com/clr2of8/DPAT |
| Group3r | rien | Cherche les GPO (stratégies de groupe) mal configurées. | https://github.com/Group3r/Group3r |

## Mots de passe et audit d'authentification (9)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| SecLists | rien | La grande collection de listes (mots de passe, noms d'utilisateurs, chemins web). (données) | https://github.com/danielmiessler/SecLists |
| Hashcat | rien | Le casseur de hashs le plus rapide (processeur graphique), pour tester la robustesse des mots de passe. | https://github.com/hashcat/hashcat |
| John the Ripper | rien | Casseur de mots de passe classique, très polyvalent. | https://github.com/openwall/john |
| THC-Hydra | rien | Teste des mots de passe sur de nombreux services (SSH, RDP, web…). | https://github.com/vanhauser-thc/thc-hydra |
| CUPP | rien | Génère une liste de mots de passe probables à partir du profil d'une cible. | https://github.com/Mebus/cupp |
| Patator | rien | Force brute modulaire et plus fiable que Hydra pour certains services. | https://github.com/lanjelot/patator |
| CeWL | rien | Fabrique une liste de mots à partir d'un site web (listes ciblées). | https://github.com/digininja/CeWL |
| Name-That-Hash | rien | Identifie le type d'un hash. | https://github.com/bee-san/Name-That-Hash |
| Medusa | rien | Force brute rapide et parallèle sur plusieurs services. | https://github.com/jmk-foofus/medusa |

## Sans fil (9)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| airgeddon | rien | Menu tout-en-un d'audit Wi-Fi qui pilote d'autres outils. | https://github.com/v1s1t0r1sh3r3/airgeddon |
| Aircrack-ng | rien | La suite d'audit Wi-Fi : capture, analyse, test de clés WEP/WPA. (Windows limité) | https://github.com/aircrack-ng/aircrack-ng |
| hcxtools | rien | Convertit les captures Wi-Fi pour Hashcat. | https://github.com/ZerBea/hcxtools |
| Kismet | rien | Détecte et analyse les réseaux Wi-Fi et Bluetooth autour de toi. | https://github.com/kismetwireless/kismet |
| hcxdumptool | rien | Capture du trafic Wi-Fi pour auditer les clés WPA. | https://github.com/ZerBea/hcxdumptool |
| Reaver (fork t6x) | rien | Teste la faiblesse du WPS sur un routeur. | https://github.com/t6x/reaver-wps-fork-t6x |
| Wifite2 | rien | Automatise l'audit de réseaux Wi-Fi. | https://github.com/kimocoder/wifite2 |
| Sparrow-WiFi | rien | Analyseur Wi-Fi et Bluetooth graphique pour Linux. | https://github.com/ghostop14/sparrow-wifi |
| Wifit3 | rien | Version de Wifite qui marche avec un adaptateur USB, multiplateforme. | https://github.com/derv82/wifit3 |

## Analyse réseau et forensic (19)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| Ghidra | rien | Désassembleur et décompilateur pour étudier un programme. | https://github.com/NationalSecurityAgency/ghidra |
| CyberChef | rien | « Couteau suisse » du web pour encoder, décoder et analyser des données. | https://github.com/gchq/CyberChef |
| radare2 | rien | Boîte à outils d'ingénierie inverse en ligne de commande. | https://github.com/radareorg/radare2 |
| Wireshark | rien | L'analyseur de trafic réseau de référence. | https://github.com/wireshark/wireshark |
| YARA | rien | Décrit et recherche des motifs dans des fichiers (analyse de logiciels malveillants). | https://github.com/VirusTotal/yara |
| ntopng (Community) | rien | Supervision du trafic réseau en temps réel (édition Community gratuite). (édition Community) | https://github.com/ntop/ntopng |
| Zeek | rien | Analyse le trafic réseau et produit des journaux détaillés. | https://github.com/zeek/zeek |
| Arkime | rien | Capture et recherche de paquets réseau à grande échelle. | https://github.com/arkime/arkime |
| GRR Rapid Response | rien | Cadre de réponse à incident à distance (agent + serveur). | https://github.com/google/grr |
| Volatility 3 | rien | Analyse la mémoire vive d'une machine pour une investigation. (licence Volatility (VSL), libre) | https://github.com/volatilityfoundation/volatility3 |
| Velociraptor | rien | Collecte et chasse aux traces sur de nombreuses machines (DFIR). | https://github.com/Velocidex/velociraptor |
| Chainsaw | rien | Cherche vite des traces suspectes dans les journaux d'événements Windows. | https://github.com/WithSecureOpenSource/chainsaw |
| Hayabusa | rien | Chasse aux menaces dans les journaux d'événements Windows. | https://github.com/Yamato-Security/hayabusa |
| Autopsy | rien | Interface d'analyse forensique de disques, en Windows. | https://github.com/sleuthkit/autopsy |
| tcpdump | rien | Capture et affiche le trafic réseau en ligne de commande. | https://github.com/the-tcpdump-group/tcpdump |
| The Sleuth Kit | rien | Outils en ligne de commande pour analyser les disques et systèmes de fichiers. | https://github.com/sleuthkit/sleuthkit |
| Plaso (log2timeline) | rien | Construit une chronologie des événements à partir de traces d'un système. | https://github.com/log2timeline/plaso |
| Zircolite | rien | Applique des règles Sigma sur des journaux Windows ou Linux. | https://github.com/wagga40/Zircolite |
| Outils Zimmerman | rien | Outils de forensic Windows (registre, journaux, artefacts). | https://github.com/EricZimmerman/Get-ZimmermanTools |

## Défense, détection et durcissement (33)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| Uptime Kuma | rien | Surveille la disponibilité de sites et services avec alertes. | https://github.com/louislam/uptime-kuma |
| Vaultwarden | rien | Serveur de mots de passe compatible Bitwarden, auto-hébergé. | https://github.com/dani-garcia/vaultwarden |
| Pi-hole | rien | Bloque publicités et domaines malveillants au niveau du DNS du réseau. | https://github.com/pi-hole/pi-hole |
| AdGuard Home | rien | Filtrage DNS du réseau, avec interface simple. | https://github.com/AdguardTeam/AdGuardHome |
| KeePassXC | rien | Gestionnaire de mots de passe local et chiffré. | https://github.com/keepassxreboot/keepassxc |
| osquery | rien | Interroge un poste ou serveur comme une base SQL pour voir son état de sécurité. | https://github.com/osquery/osquery |
| Fail2ban | rien | Bloque les adresses qui tentent des connexions en force brute. | https://github.com/fail2ban/fail2ban |
| Wazuh | rien | Surveillance de sécurité : journaux, intégrité des fichiers, détection de menaces, conformité. | https://github.com/wazuh/wazuh |
| CrowdSec | rien | Détecte et bloque les adresses malveillantes, avec une liste partagée par la communauté. | https://github.com/crowdsecurity/crowdsec |
| Gophish | rien | Campagnes de simulation d'hameçonnage pour sensibiliser les employés. Avec accord écrit seulement. | https://github.com/gophish/gophish |
| Atomic Red Team | rien | Petits tests d'attaque pour vérifier que ta détection les voit. | https://github.com/redcanaryco/atomic-red-team |
| VeraCrypt | rien | Chiffrement de disques et de conteneurs. | https://github.com/veracrypt/VeraCrypt |
| Sigma | rien | Format ouvert de règles de détection pour journaux, avec des milliers de règles. (règles sous licence DRL) | https://github.com/SigmaHQ/sigma |
| Falco | rien | Détection d'activités suspectes sur des conteneurs et serveurs Linux. | https://github.com/falcosecurity/falco |
| ClamAV | rien | Antivirus libre, utile sur serveurs de messagerie et fichiers. | https://github.com/Cisco-Talos/clamav |
| MITRE Caldera | rien | Plateforme d'émulation d'adversaire pour tester ses défenses. | https://github.com/apache/caldera |
| Infection Monkey | rien | Simule une attaque dans ton réseau pour trouver les chemins faibles. | https://github.com/guardicore/monkey |
| Suricata | rien | Détection et blocage d'intrusions réseau. | https://github.com/OISF/suricata |
| Cowrie | rien | Honeypot SSH/Telnet qui enregistre les attaques. | https://github.com/cowrie/cowrie |
| MISP | rien | Plateforme de partage d'informations sur les menaces. | https://github.com/MISP/MISP |
| pfSense CE | rien | Pare-feu et routeur libre, édition Community. (édition Community) | https://github.com/pfsense/pfsense |
| DevSec Hardening | rien | Rôles Ansible pour durcir Linux, SSH, nginx et MySQL. | https://github.com/dev-sec/ansible-collection-hardening |
| Harden-Windows-Security | rien | Guide et scripts pour durcir Windows 10/11 (Defender, BitLocker, pare-feu…). | https://github.com/HotCakeX/Harden-Windows-Security |
| OPNsense | rien | Pare-feu et routeur libre, clair et à jour, idéal pour une petite structure. | https://github.com/opnsense/core |
| Coraza WAF | rien | Pare-feu applicatif web libre, compatible avec les règles ModSecurity. | https://github.com/corazawaf/coraza |
| Snort 3 | rien | Système de détection d'intrusions réseau historique. | https://github.com/snort3/snort3 |
| OWASP CRS | rien | Règles génériques pour pare-feu applicatif web (ModSecurity, Coraza). (données) | https://github.com/coreruleset/coreruleset |
| sysmon-modular | rien | Configuration modulaire de Sysmon pour mieux journaliser Windows. | https://github.com/olafhartong/sysmon-modular |
| OpenCanary | rien | Faux services « pièges » qui alertent quand quelqu'un les touche. | https://github.com/thinkst/opencanary |
| hardentools | rien | Désactive d'un clic des fonctions Windows risquées (macros, scripts, PDF). | https://github.com/hardentools/hardentools |
| Stratus Red Team | rien | Simule des attaques dans le cloud (dont Azure) pour tester la détection. | https://github.com/DataDog/stratus-red-team |
| Caddy WAF | rien | Pare-feu applicatif web pour le serveur Caddy (règles regex, filtrage IP, limitation de débit). | https://github.com/fabriziosalmi/caddy-waf |
| Sigwood | rien | Chasse aux menaces en local dans les journaux que tu as déjà (Zeek, Pi-hole, syslog). | https://github.com/helixmap/sigwood |

## Pentest et audit assistés par IA ou LLM (21)

| Outil | Besoin | Rôle | Lien |
| --- | --- | --- | --- |
| promptfoo | rien | Teste et attaque des prompts et applications LLM. | https://github.com/promptfoo/promptfoo |
| PentestGPT | jetons payants ou modèle local | Assistant de pentest guidé par LLM : propose les étapes et commandes. | https://github.com/GreyDGL/PentestGPT |
| garak | jetons payants ou modèle local | Teste la robustesse d'un LLM (injections, fuites, contenus dangereux). | https://github.com/NVIDIA/garak |
| Vulnhuntr | jetons payants ou modèle local | Cherche des failles dans du code Python à l'aide d'un LLM. | https://github.com/protectai/vulnhuntr |
| hackingBuddyGPT | jetons payants ou modèle local | Recherche : un LLM tente de monter en privilèges sur Linux dans un labo. | https://github.com/ipa-lab/hackingBuddyGPT |
| Nebula | jetons payants ou modèle local | Assistant IA en ligne de commande pour pentest, avec modèle local possible. | https://github.com/berylliumsec/nebula |
| Strix | jetons payants ou modèle local | Agents IA autonomes qui testent une application et prouvent les failles dans un bac à sable Docker. | https://github.com/usestrix/strix |
| Shannon | jetons payants ou modèle local | Pentester IA pour applications et API web, qui lit aussi le code source. | https://github.com/KeygraphHQ/shannon |
| PentAGI | jetons payants ou modèle local | Système d'agents IA autonomes pour tâches de pentest complexes. | https://github.com/vxcontrol/pentagi |
| SkillSpector | rien | Analyse la sécurité des « skills » d'agents IA (motifs malveillants, failles). | https://github.com/NVIDIA/SkillSpector |
| ARTEX | jetons payants ou modèle local | Système de pentest autonome multi-agents (traduction anglaise d'un projet chinois). | https://github.com/BaaRai/ARTEX |
| DeepAudit | jetons payants ou modèle local | Audit de code assisté par agents IA, avec vérification en bac à sable et rapport. | https://github.com/lintsinghua/DeepAudit |
| Decepticon | jetons payants ou modèle local | Agent autonome pour exercices de type Red Team. | https://github.com/BitterSecurity/Decepticon |
| RedAmon | jetons payants ou modèle local | Cadre de pentest IA auto-hébergé qui cartographie la surface d'attaque. | https://github.com/samugit83/redamon |
| PentestAgent | jetons payants ou modèle local | Cadre d'agent IA pour tests de sécurité en boîte noire et bug bounty. | https://github.com/GH05TCREW/pentestagent |
| mcp-scan | rien | Analyse les serveurs MCP et les outils d'agents pour y trouver des risques. | https://github.com/snyk/agent-scan |
| open-kritt | jetons payants ou modèle local | Outil de recherche de vulnérabilités avec agents IA, auto-hébergé. | https://github.com/Kritt-ai/open-kritt |
| pentest-ai | jetons payants ou modèle local | Pentester IA qui rejoue chaque exploit pour confirmer la faille avant de la signaler. | https://github.com/0xSteph/pentest-ai |
| Burp AI Agent | jetons payants ou modèle local | Extension Burp Suite qui ajoute analyse assistée par IA et outils MCP. | https://github.com/six2dez/burp-ai-agent |
| Xalgorix | jetons payants ou modèle local | Agent IA de pentest autonome qui vérifie chaque faille par exploitation. | https://github.com/xalgorix/xalgorix |
| DorkAgent | jetons payants ou modèle local | Automatise les recherches Google dorks avec un LLM. | https://github.com/yee-yore/DorkAgent |
