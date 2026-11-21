#!/usr/bin/env python3
# Genere chantier/synthese_familles.md a partir de vigie/docs_outils.json
# Mapping facette -> famille (diag gratuit / audit / securisation / gate)
import json, datetime, collections

MAP = {
  # FAMILLE 1 - DIAG GRATUIT EXTERNE (passif, info publique, a distance)
  "urls":"diag","domaines":"diag","pseudos":"diag","email":"diag","instagram":"diag",
  "telephone":"diag","documents":"diag","darkweb":"diag","geoloc":"diag","ip":"diag",
  "easm":"diag","metadonnees":"diag","verification":"diag","graphe":"diag",
  "archivage":"diag","dns":"diag",
  # FAMILLE 2 - AUDIT PAYANT (scan actif autorise, audit de config, pentest web lecture)
  "ports":"audit","failles":"audit","web-scanner":"audit","tls":"audit","cloud":"audit",
  "kubernetes":"audit","iac":"audit","conformite":"audit","sbom":"audit","dependances":"audit",
  "azure":"audit","m365":"audit","azure-ad":"audit","audit-ad":"audit","audit-mdp":"audit",
  "reseau":"audit","reseau-local":"audit","fingerprinting":"audit","multi":"audit",
  "crawl":"audit","params":"audit","js":"audit","web-proxy":"audit","proxy":"audit",
  "fuzzing":"audit","secrets":"audit","sbom ":"audit",
  # FAMILLE 3 - SECURISATION (defensif, durcissement, detection, DFIR/forensic)
  "durcissement":"secu","pare-feu":"secu","waf":"secu","ids":"secu","ips":"secu",
  "honeypot":"secu","edr":"secu","siem":"secu","antivirus":"secu","detection":"secu",
  "runtime":"secu","journalisation":"secu","supervision":"secu","supervision-reseau":"secu",
  "threat-hunting":"secu","nsm":"secu","detection-malware":"secu","chiffrement":"secu",
  "sast-ia":"secu","sensibilisation":"secu","audit-code-ia":"secu","analyse-donnees":"secu",
  "capture-reseau":"secu","analyse-reseau":"secu","reverse-engineering":"secu",
  "forensic-disque":"secu","forensic-memoire":"secu","dfir-endpoint":"secu","dfir-triage":"secu",
  "dfir-timeline":"secu","dfir-artefacts":"secu","code":"secu","serveur-web":"secu",
  "ia-supply-chain":"secu","llm-scan":"secu","cti":"secu","audit-wifi":"secu",
  # FAMILLE 4 - GATE (offensif, autorisation signee, jamais en auto ni en diag gratuit)
  "offensif":"gate","offensif-ad":"gate","offensif-agent":"gate","offensif-wifi":"gate",
  "offensif-mdp":"gate","offensif-assistant":"gate","offensif-test":"gate",
  "offensif-dangereux":"gate","osint-offensif":"gate","bruteforce":"gate","privesc":"gate",
  "exploitation":"gate","sqli":"gate","rce":"gate","xss":"gate","ssrf":"gate","mitm":"gate",
  "jwt":"gate","oob":"gate","exploits":"gate","wordpress":"gate","mdp":"gate","hash-id":"gate",
  "wordlists":"gate","llm-redteam":"gate","orchestrateur":"gate",
}

NOMS = {"diag":"1. DIAG GRATUIT EXTERNE (passif, info publique)",
        "audit":"2. AUDIT PAYANT (scan actif, sur autorisation)",
        "secu":"3. SECURISATION (defensif, durcissement, DFIR)",
        "gate":"4. GATE (offensif, autorisation signee uniquement)"}
ORDRE = ["diag","audit","secu","gate"]
# facettes a signaler comme zones grises (double usage)
GRISES = {"audit-wifi","secrets","osint-offensif","llm-scan","cti","dns","fingerprinting"}

d = json.load(open("vigie/docs_outils.json"))
outils = d if isinstance(d, list) else d.get("outils", [])
par_fam = collections.defaultdict(list)
non_classe = collections.defaultdict(list)
introuv = []
for o in outils:
    if o.get("statut") == "introuvable":
        introuv.append(o); continue
    f = o.get("facette", "")
    fam = MAP.get(f)
    if fam: par_fam[fam].append(o)
    else: non_classe[f].append(o.get("nom","?"))

L = []
L.append("# Vigie - Synthese des 222 outils en 4 familles")
L.append(f"\n_Genere le {datetime.date.today().isoformat()} a partir de docs_outils.json. "
         "Classement base sur la facette taggee pendant le chantier ; les cas a double usage "
         "sont listes en bas (section Zones grises)._\n")
tot = sum(len(v) for v in par_fam.values())
L.append("## Repartition\n")
L.append("| Famille | Outils | Role dans Vigie |")
L.append("|---|---|---|")
roles = {"diag":"pipeline auto du diag gratuit (public only)",
         "audit":"offre audit (scan actif + accord simple)",
         "secu":"offre securisation / hardening",
         "gate":"jamais en auto, jamais en gratuit (accord signe)"}
for k in ORDRE:
    L.append(f"| {NOMS[k]} | {len(par_fam[k])} | {roles[k]} |")
L.append(f"| **Total classe** | **{tot}** | |")
L.append(f"| Introuvables | {len(introuv)} | {', '.join(o.get('nom','?') for o in introuv)} |")

for k in ORDRE:
    L.append(f"\n## {NOMS[k]}  ({len(par_fam[k])})\n")
    for o in sorted(par_fam[k], key=lambda x:(x.get('categorie',''), x.get('nom',''))):
        g = "  [zone grise]" if o.get("facette") in GRISES else ""
        L.append(f"- **{o.get('nom','?')}** — {o.get('categorie','?')}{g}")

if non_classe:
    L.append("\n## Facettes NON classees (a trancher)\n")
    for f, noms in sorted(non_classe.items()):
        L.append(f"- `{f}` : {', '.join(noms)}")

L.append("\n## Zones grises (double usage, a arbitrer par Anass)\n")
L.append("- **audit-wifi** (Kismet, Sparrow-WiFi) : passif/surveillance → range en Securisation, "
         "mais necessite d'etre sur place (hors diag gratuit a distance).")
L.append("- **secrets** : secrets exposes sur sources PUBLIQUES (GitHub public) = diag gratuit ; "
         "secrets dans le code du client = audit. Range en Audit par defaut.")
L.append("- **osint-offensif** (DorkAgent) : OSINT via Google = zone grise ; range en Gate par prudence.")
L.append("- **llm-scan / ia-supply-chain** (garak, promptfoo, mcp-scan, SkillSpector) : tester SES PROPRES "
         "modeles/MCP = defensif → Securisation ; tester ceux d'un tiers = Gate.")
L.append("- **cti** : veille menace (info publique) — pourrait aussi nourrir le diag gratuit.")
L.append("- **dns / fingerprinting** : passif = diag, actif = audit.")

open("chantier/synthese_familles.md","w").write("\n".join(L)+"\n")
print("Ecrit : chantier/synthese_familles.md")
print("Repartition :", {k:len(par_fam[k]) for k in ORDRE}, "| total", tot, "| introuvables", len(introuv))
if non_classe:
    print("NON CLASSEES :", dict((f,len(n)) for f,n in non_classe.items()))
else:
    print("Toutes les facettes sont classees.")
