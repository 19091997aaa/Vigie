# Vigie - Synthese des 222 outils en 4 familles

_Genere le 2026-11-21 a partir de docs_outils.json. Classement base sur la facette taggee pendant le chantier ; les cas a double usage sont listes en bas (section Zones grises)._

## Repartition

| Famille | Outils | Role dans Vigie |
|---|---|---|
| 1. DIAG GRATUIT EXTERNE (passif, info publique) | 42 | pipeline auto du diag gratuit (public only) |
| 2. AUDIT PAYANT (scan actif, sur autorisation) | 57 | offre audit (scan actif + accord simple) |
| 3. SECURISATION (defensif, durcissement, DFIR) | 55 | offre securisation / hardening |
| 4. GATE (offensif, autorisation signee uniquement) | 66 | jamais en auto, jamais en gratuit (accord signe) |
| **Total classe** | **220** | |
| Introuvables | 2 | Xingrin, ARL-Next |

## 1. DIAG GRATUIT EXTERNE (passif, info publique)  (42)

- **AdGuard Home** — Défense, détection et durcissement  [zone grise]
- **Pi-hole** — Défense, détection et durcissement  [zone grise]
- **EyeWitness** — OSINT : ma société est-elle bien référencée ?
- **Lighthouse** — OSINT : ma société est-elle bien référencée ?
- **LinkChecker** — OSINT : ma société est-elle bien référencée ?
- **OWASP Amass** — OSINT : ma société est-elle bien référencée ?
- **Pa11y** — OSINT : ma société est-elle bien référencée ?
- **SSLyze** — OSINT : ma société est-elle bien référencée ?
- **Subfinder** — OSINT : ma société est-elle bien référencée ?
- **Unlighthouse** — OSINT : ma société est-elle bien référencée ?
- **Web-Check** — OSINT : ma société est-elle bien référencée ?
- **WhatWeb** — OSINT : ma société est-elle bien référencée ?
- **checkdmarc** — OSINT : ma société est-elle bien référencée ?
- **dnsrecon** — OSINT : ma société est-elle bien référencée ?
- **dnstwist** — OSINT : ma société est-elle bien référencée ?
- **dnsx** — OSINT : ma société est-elle bien référencée ?
- **gowitness** — OSINT : ma société est-elle bien référencée ?
- **httpx** — OSINT : ma société est-elle bien référencée ?
- **sitespeed.io** — OSINT : ma société est-elle bien référencée ?
- **uncover** — OSINT : ma société est-elle bien référencée ?
- **ArchiveBox** — OSINT : pseudos, e-mails, images, métadonnées
- **Datashare** — OSINT : pseudos, e-mails, images, métadonnées
- **ExifTool** — OSINT : pseudos, e-mails, images, métadonnées
- **Exiv2** — OSINT : pseudos, e-mails, images, métadonnées
- **Flowsint** — OSINT : pseudos, e-mails, images, métadonnées
- **GHunt** — OSINT : pseudos, e-mails, images, métadonnées
- **Holehe** — OSINT : pseudos, e-mails, images, métadonnées
- **InVID-WeVerify** — OSINT : pseudos, e-mails, images, métadonnées
- **Instaloader** — OSINT : pseudos, e-mails, images, métadonnées
- **Maigret** — OSINT : pseudos, e-mails, images, métadonnées
- **Metagoofil** — OSINT : pseudos, e-mails, images, métadonnées
- **PhoneInfoga** — OSINT : pseudos, e-mails, images, métadonnées
- **Robin** — OSINT : pseudos, e-mails, images, métadonnées
- **Sherlock** — OSINT : pseudos, e-mails, images, métadonnées
- **Social Analyzer** — OSINT : pseudos, e-mails, images, métadonnées
- **Toutatis** — OSINT : pseudos, e-mails, images, métadonnées
- **auto-archiver** — OSINT : pseudos, e-mails, images, métadonnées
- **geo-sleuth** — OSINT : pseudos, e-mails, images, métadonnées
- **theHarvester** — OSINT : pseudos, e-mails, images, métadonnées
- **user-scanner** — OSINT : pseudos, e-mails, images, métadonnées
- **gau** — Pentest web
- **IVRE** — Reconnaissance et scan réseau

## 2. AUDIT PAYANT (scan actif, sur autorisation)  (57)

- **Adalanche** — Active Directory
- **BloodHound** — Active Directory
- **DPAT** — Active Directory
- **Locksmith** — Active Directory
- **Hashcat** — Mots de passe et audit d'authentification
- **John the Ripper** — Mots de passe et audit d'authentification
- **Betterleaks** — OSINT : ma société est-elle bien référencée ?  [zone grise]
- **Gitleaks** — OSINT : ma société est-elle bien référencée ?  [zone grise]
- **TruffleHog** — OSINT : ma société est-elle bien référencée ?  [zone grise]
- **cloud_enum** — OSINT : ma société est-elle bien référencée ?
- **OpenOSINT** — OSINT : pseudos, e-mails, images, métadonnées
- **Recon-ng** — OSINT : pseudos, e-mails, images, métadonnées
- **SpiderFoot** — OSINT : pseudos, e-mails, images, métadonnées
- **Arjun** — Pentest web
- **Burp Suite Community** — Pentest web
- **Katana** — Pentest web
- **Nikto** — Pentest web
- **OWASP ZAP** — Pentest web
- **Retire.js** — Pentest web
- **Wapiti** — Pentest web
- **Wfuzz** — Pentest web
- **ffuf** — Pentest web
- **mitmproxy** — Pentest web
- **sslscan** — Pentest web
- **Angry IP Scanner** — Reconnaissance et scan réseau
- **Masscan** — Reconnaissance et scan réseau
- **Naabu** — Reconnaissance et scan réseau
- **Nerva** — Reconnaissance et scan réseau  [zone grise]
- **Nmap** — Reconnaissance et scan réseau
- **RustScan** — Reconnaissance et scan réseau
- **ZMap** — Reconnaissance et scan réseau
- **arp-scan** — Reconnaissance et scan réseau
- **nmap-vulners** — Reconnaissance et scan réseau
- **tlsx** — Reconnaissance et scan réseau
- **AADInternals** — Scan de vulnérabilités et audit de configuration
- **AzureHound** — Scan de vulnérabilités et audit de configuration
- **Checkov** — Scan de vulnérabilités et audit de configuration
- **ComplianceAsCode** — Scan de vulnérabilités et audit de configuration
- **Grype** — Scan de vulnérabilités et audit de configuration
- **Kubescape** — Scan de vulnérabilités et audit de configuration
- **Maester** — Scan de vulnérabilités et audit de configuration
- **MicroBurst** — Scan de vulnérabilités et audit de configuration
- **Microsoft365DSC** — Scan de vulnérabilités et audit de configuration
- **Monkey365** — Scan de vulnérabilités et audit de configuration
- **Nuclei** — Scan de vulnérabilités et audit de configuration
- **Nuclei Templates** — Scan de vulnérabilités et audit de configuration
- **OWASP Dependency-Check** — Scan de vulnérabilités et audit de configuration
- **OpenSCAP** — Scan de vulnérabilités et audit de configuration
- **OpenVAS (Greenbone Community)** — Scan de vulnérabilités et audit de configuration
- **PSRule for Azure** — Scan de vulnérabilités et audit de configuration
- **Prowler** — Scan de vulnérabilités et audit de configuration
- **ROADtools** — Scan de vulnérabilités et audit de configuration
- **ScoutSuite** — Scan de vulnérabilités et audit de configuration
- **ScubaGear** — Scan de vulnérabilités et audit de configuration
- **Syft** — Scan de vulnérabilités et audit de configuration
- **Trivy** — Scan de vulnérabilités et audit de configuration
- **kube-bench** — Scan de vulnérabilités et audit de configuration

## 3. SECURISATION (defensif, durcissement, DFIR)  (55)

- **Arkime** — Analyse réseau et forensic
- **Autopsy** — Analyse réseau et forensic
- **Chainsaw** — Analyse réseau et forensic
- **CyberChef** — Analyse réseau et forensic
- **GRR Rapid Response** — Analyse réseau et forensic
- **Ghidra** — Analyse réseau et forensic
- **Hayabusa** — Analyse réseau et forensic
- **Outils Zimmerman** — Analyse réseau et forensic
- **Plaso (log2timeline)** — Analyse réseau et forensic
- **The Sleuth Kit** — Analyse réseau et forensic
- **Velociraptor** — Analyse réseau et forensic
- **Volatility 3** — Analyse réseau et forensic
- **Wireshark** — Analyse réseau et forensic
- **YARA** — Analyse réseau et forensic
- **Zeek** — Analyse réseau et forensic
- **Zircolite** — Analyse réseau et forensic
- **ntopng (Community)** — Analyse réseau et forensic
- **radare2** — Analyse réseau et forensic
- **tcpdump** — Analyse réseau et forensic
- **Caddy WAF** — Défense, détection et durcissement
- **ClamAV** — Défense, détection et durcissement
- **Coraza WAF** — Défense, détection et durcissement
- **Cowrie** — Défense, détection et durcissement
- **CrowdSec** — Défense, détection et durcissement
- **DevSec Hardening** — Défense, détection et durcissement
- **Fail2ban** — Défense, détection et durcissement
- **Falco** — Défense, détection et durcissement
- **Gophish** — Défense, détection et durcissement
- **Harden-Windows-Security** — Défense, détection et durcissement
- **MISP** — Défense, détection et durcissement  [zone grise]
- **OPNsense** — Défense, détection et durcissement
- **OWASP CRS** — Défense, détection et durcissement
- **OpenCanary** — Défense, détection et durcissement
- **Sigma** — Défense, détection et durcissement
- **Sigwood** — Défense, détection et durcissement
- **Snort 3** — Défense, détection et durcissement
- **Suricata** — Défense, détection et durcissement
- **Uptime Kuma** — Défense, détection et durcissement
- **VeraCrypt** — Défense, détection et durcissement
- **Wazuh** — Défense, détection et durcissement
- **hardentools** — Défense, détection et durcissement
- **osquery** — Défense, détection et durcissement
- **pfSense CE** — Défense, détection et durcissement
- **sysmon-modular** — Défense, détection et durcissement
- **DeepAudit** — Pentest et audit assistés par IA ou LLM
- **SkillSpector** — Pentest et audit assistés par IA ou LLM
- **Vulnhuntr** — Pentest et audit assistés par IA ou LLM
- **garak** — Pentest et audit assistés par IA ou LLM  [zone grise]
- **mcp-scan** — Pentest et audit assistés par IA ou LLM
- **open-kritt** — Pentest et audit assistés par IA ou LLM
- **Kismet** — Sans fil  [zone grise]
- **Sparrow-WiFi** — Sans fil  [zone grise]
- **HardeningKitty** — Scan de vulnérabilités et audit de configuration
- **Lynis** — Scan de vulnérabilités et audit de configuration
- **Semgrep** — Scan de vulnérabilités et audit de configuration

## 4. GATE (offensif, autorisation signee uniquement)  (66)

- **Certipy** — Active Directory
- **Group3r** — Active Directory
- **Impacket** — Active Directory
- **NetExec** — Active Directory
- **Responder** — Active Directory
- **SMBMap** — Active Directory
- **enum4linux-ng** — Active Directory
- **kerbrute** — Active Directory
- **ldapdomaindump** — Active Directory
- **mitm6** — Active Directory
- **Atomic Red Team** — Défense, détection et durcissement
- **Infection Monkey** — Défense, détection et durcissement
- **KeePassXC** — Défense, détection et durcissement
- **MITRE Caldera** — Défense, détection et durcissement
- **Stratus Red Team** — Défense, détection et durcissement
- **Vaultwarden** — Défense, détection et durcissement
- **CUPP** — Mots de passe et audit d'authentification
- **CeWL** — Mots de passe et audit d'authentification
- **Medusa** — Mots de passe et audit d'authentification
- **Name-That-Hash** — Mots de passe et audit d'authentification
- **Patator** — Mots de passe et audit d'authentification
- **SecLists** — Mots de passe et audit d'authentification
- **THC-Hydra** — Mots de passe et audit d'authentification
- **ARTEX** — Pentest et audit assistés par IA ou LLM
- **Burp AI Agent** — Pentest et audit assistés par IA ou LLM
- **Decepticon** — Pentest et audit assistés par IA ou LLM
- **DorkAgent** — Pentest et audit assistés par IA ou LLM  [zone grise]
- **Nebula** — Pentest et audit assistés par IA ou LLM
- **PentAGI** — Pentest et audit assistés par IA ou LLM
- **PentestAgent** — Pentest et audit assistés par IA ou LLM
- **PentestGPT** — Pentest et audit assistés par IA ou LLM
- **RedAmon** — Pentest et audit assistés par IA ou LLM
- **Shannon** — Pentest et audit assistés par IA ou LLM
- **Strix** — Pentest et audit assistés par IA ou LLM
- **Xalgorix** — Pentest et audit assistés par IA ou LLM
- **hackingBuddyGPT** — Pentest et audit assistés par IA ou LLM
- **pentest-ai** — Pentest et audit assistés par IA ou LLM
- **promptfoo** — Pentest et audit assistés par IA ou LLM
- **Commix** — Pentest web
- **Dalfox** — Pentest web
- **Exploit-DB (searchsploit)** — Pentest web
- **Gobuster** — Pentest web
- **Interactsh** — Pentest web
- **Metasploit Framework** — Pentest web
- **SSRFmap** — Pentest web
- **WPProbe** — Pentest web
- **XSStrike** — Pentest web
- **dirsearch** — Pentest web
- **feroxbuster** — Pentest web
- **jwt_tool** — Pentest web
- **sqlmap** — Pentest web
- **AutoRecon** — Reconnaissance et scan réseau
- **Bettercap** — Reconnaissance et scan réseau
- **OWASP Nettacker** — Reconnaissance et scan réseau
- **Osmedeus** — Reconnaissance et scan réseau
- **reconftw** — Reconnaissance et scan réseau
- **Aircrack-ng** — Sans fil
- **Reaver (fork t6x)** — Sans fil
- **Wifit3** — Sans fil
- **Wifite2** — Sans fil
- **airgeddon** — Sans fil
- **hcxdumptool** — Sans fil
- **hcxtools** — Sans fil
- **PEASS-ng (WinPEAS/LinPEAS)** — Scan de vulnérabilités et audit de configuration
- **PrivescCheck** — Scan de vulnérabilités et audit de configuration
- **linux-smart-enumeration** — Scan de vulnérabilités et audit de configuration

## Zones grises (double usage, a arbitrer par Anass)

- **audit-wifi** (Kismet, Sparrow-WiFi) : passif/surveillance → range en Securisation, mais necessite d'etre sur place (hors diag gratuit a distance).
- **secrets** : secrets exposes sur sources PUBLIQUES (GitHub public) = diag gratuit ; secrets dans le code du client = audit. Range en Audit par defaut.
- **osint-offensif** (DorkAgent) : OSINT via Google = zone grise ; range en Gate par prudence.
- **llm-scan / ia-supply-chain** (garak, promptfoo, mcp-scan, SkillSpector) : tester SES PROPRES modeles/MCP = defensif → Securisation ; tester ceux d'un tiers = Gate.
- **cti** : veille menace (info publique) — pourrait aussi nourrir le diag gratuit.
- **dns / fingerprinting** : passif = diag, actif = audit.
