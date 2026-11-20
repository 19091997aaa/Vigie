"""Essais sans internet : on remplace le réseau par des réponses préparées.

    python3 -m unittest discover -s tests
"""
import json
import os
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigie import (autorisation, banc, cli, comparaison, decouverte,  # noqa: E402
                   installeur,
                   lanceur,
                   interface, outils, pdf, rapport, reseau, scenarios)
from vigie.modeles import (CRITIQUE, IMPORTANT, INFO, OK, Cible, Constat,  # noqa: E402
                           ControleImpossible, fusionner, note)
from vigie.modules import MODULES, conformite, domaines, mail, pseudos, site  # noqa: E402

CIBLE = Cible("ex.fr", "Société <Test>")
BON_DNS = {
    ("ex.fr", "A"): ["203.0.113.5"],
    ("ex.fr", "MX"): ["10 mx.ex.fr."],
    ("ex.fr", "TXT"): ["v=spf1 include:_spf.google.com -all", "autre"],
    ("_dmarc.ex.fr", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@ex.fr"],
    ("google._domainkey.ex.fr", "TXT"): ["v=DKIM1; k=rsa; p=abc"],
}
SITE_SEUL = {("ex.fr", "A"): ["203.0.113.5"]}
BONS_ENTETES = {"strict-transport-security": "max-age=1", "content-security-policy": "x",
                "x-content-type-options": "nosniff", "x-frame-options": "DENY"}


def faux_dns(table):
    return lambda nom, typ: table.get((nom, typ), [])


def reseau_coupe(nom, typ):
    raise reseau.ErreurReseau("pas d'internet")


class Base(unittest.TestCase):
    def setUp(self):
        self._sauve = (reseau.dns, site._ouvrir, site._jours_certificat, outils.executer)

    def tearDown(self):
        reseau.dns, site._ouvrir, site._jours_certificat, outils.executer = self._sauve

    def site_propre(self):
        site._jours_certificat = lambda d: 80
        site._ouvrir = lambda url: ("https://ex.fr/", 200, dict(BONS_ENTETES))


class Mail(Base):
    def niveaux(self, table):
        reseau.dns = faux_dns(table)
        constats, _ = mail.analyser(CIBLE)
        return [c.niveau for c in constats], constats

    def test_domaine_sans_rien(self):
        self.assertEqual(self.niveaux({})[0].count(CRITIQUE), 2)

    def test_domaine_bien_regle(self):
        self.assertEqual(set(self.niveaux(BON_DNS)[0]), {OK})

    def test_deux_spf_et_dmarc_none(self):
        niveaux, constats = self.niveaux({("ex.fr", "TXT"): ["v=spf1 a ~all", "v=spf1 mx ?all"],
                                          ("_dmarc.ex.fr", "TXT"): ["v=DMARC1; p=none"]})
        self.assertEqual(niveaux.count(IMPORTANT), 2)
        self.assertTrue(any("2 enregistrements" in c.titre for c in constats))


class Site(Base):
    def test_site_propre(self):
        reseau.dns = faux_dns(SITE_SEUL)
        self.site_propre()
        constats, brut = site.analyser(CIBLE)
        self.assertEqual({c.niveau for c in constats}, {OK})
        self.assertEqual(brut["jours_certificat"], 80)

    def test_site_fragile(self):
        reseau.dns = faux_dns(SITE_SEUL)
        site._jours_certificat = lambda d: 5
        site._ouvrir = lambda url: (url, 200, {"server": "Apache/2.4.41"})
        titres = " | ".join(c.titre for c in site.analyser(CIBLE)[0])
        for attendu in ("expire dans 5 jours", "sans chiffrement", "HSTS",
                        "version de ses logiciels"):
            self.assertIn(attendu, titres)

    def test_certificat_invalide(self):
        def casse(domaine):
            raise ssl.SSLError("certificat expiré")
        reseau.dns = faux_dns(SITE_SEUL)
        self.site_propre()
        site._jours_certificat = casse
        self.assertEqual(site.analyser(CIBLE)[0][0].niveau, CRITIQUE)

    def test_pas_de_site(self):
        reseau.dns = faux_dns({})
        constats, _ = site.analyser(CIBLE)
        self.assertEqual([c.niveau for c in constats], [INFO])

    def test_internet_coupe_ne_donne_aucun_faux_constat(self):
        reseau.dns = reseau_coupe
        with self.assertRaises(ControleImpossible):
            site.analyser(CIBLE)


class Pseudos(Base):
    SORTIE = ("[*] Checking username jdupont on:\n\n"
              "[+] GitHub: https://github.com/jdupont\n"
              "[+] Reddit: https://www.reddit.com/user/jdupont\n"
              "[-] Autre: Not Found!\n\n[*] Search completed with 2 results\n")

    def test_lecture_de_la_sortie(self):
        comptes = pseudos.lire_sortie(self.SORTIE)
        self.assertEqual([c["site"] for c in comptes], ["GitHub", "Reddit"])

    def test_refus_sans_accord(self):
        with self.assertRaises(ControleImpossible):
            pseudos.analyser(Cible("ex.fr", pseudos=["jdupont"]))
        with self.assertRaises(ControleImpossible):
            pseudos.analyser(Cible("ex.fr", accord_dirigeant=True))

    def test_pseudo_dangereux_refuse(self):
        outils.executer = lambda *a, **k: self.fail("l'outil ne doit pas être lancé")
        with self.assertRaises(ControleImpossible):
            pseudos.analyser(Cible("ex.fr", pseudos=["--json=/etc/passwd"],
                                   accord_dirigeant=True))

    def test_avec_accord(self):
        appels = []

        def faux(nom, arguments, delai=0, dossier=None):
            appels.append((nom, arguments))
            return self.SORTIE
        outils.executer = faux
        constats, brut = pseudos.analyser(Cible("ex.fr", pseudos=["jdupont"],
                                                accord_dirigeant=True))
        self.assertEqual(appels[0][0], "sherlock")
        self.assertEqual(appels[0][1][0], "jdupont")
        self.assertIn("2 comptes publics", constats[0].titre)
        self.assertEqual(len(brut["jdupont"]), 2)

    def test_outil_absent(self):
        with self.assertRaises(ControleImpossible):
            outils.executer("nuclei", ["-version"]) if not outils.disponible("nuclei") \
                else self.skipTest("nuclei est installé ici")


class Domaines(Base):
    SORTIE = json.dumps([
        {"fuzzer": "original", "domain": "exemple.fr", "dns_a": ["203.0.113.5"]},
        {"fuzzer": "omission", "domain": "exmple.fr", "dns_a": ["198.51.100.9"],
         "dns_mx": ["mx.exmple.fr"]},
        {"fuzzer": "replacement", "domain": "exemp1e.fr", "dns_a": ["198.51.100.3"]},
        {"fuzzer": "insertion", "domain": "exempple.fr"},  # non enregistré : ignoré
    ])

    def test_lecture(self):
        imitateurs = domaines.lire_sortie(self.SORTIE)
        self.assertEqual(len(imitateurs), 2)
        self.assertTrue(any(i["mx"] for i in imitateurs))

    def test_constat_important_si_mail(self):
        outils.executer = lambda *a, **k: self.SORTIE
        constats, _ = domaines.analyser(CIBLE)
        self.assertEqual(constats[0].niveau, IMPORTANT)
        self.assertIn("2 domaines", constats[0].titre)

    def test_aucun_imitateur(self):
        outils.executer = lambda *a, **k: "[]"
        constats, _ = domaines.analyser(CIBLE)
        self.assertEqual(constats[0].niveau, OK)


class Convergence(unittest.TestCase):
    def test_fusion_par_cle(self):
        constats = [
            Constat("Exposition", INFO, "DMARC faible", "e", cle="dmarc", sources=["mail"]),
            Constat("Exposition", IMPORTANT, "DMARC absent", "e2", cle="dmarc",
                    sources=["checkdmarc"]),
            Constat("Exposition", OK, "Site ok", "e3"),  # sans clé : jamais fusionné
        ]
        fusionnes = fusionner(constats)
        self.assertEqual(len(fusionnes), 2)
        dmarc = fusionnes[0]
        self.assertEqual(dmarc.niveau, IMPORTANT)          # on garde le plus grave
        self.assertEqual(set(dmarc.sources), {"mail", "checkdmarc"})  # outils réunis


class Conformite(unittest.TestCase):
    def test_sans_reponses_non_realise(self):
        with self.assertRaises(ControleImpossible):
            conformite.analyser(Cible("ex.fr"))

    def test_conforme_et_a_regler(self):
        rep = {"mfa_distance": False, "sauvegarde_testee": True, "maj_30j": True}
        constats, brut = conformite.analyser(Cible("ex.fr", reponses=rep))
        niveaux = {c.titre.split(" :")[0]: c.niveau for c in constats}
        self.assertEqual(niveaux["À régler"], CRITIQUE)   # MFA absente = critique
        self.assertEqual(niveaux["Conforme"], OK)
        # les questions non répondues sont listées à vérifier, pas comptées comme défaut
        self.assertTrue(brut["a_verifier"])
        self.assertEqual(len(constats), 3)

    def test_integration_cli_reponses(self):
        rep = {"mfa_distance": True, "sauvegarde_testee": False}
        r = cli.lancer(Cible("ex.fr", "Essai", reponses=rep), ["conformite"], date="2026-11-20")
        self.assertIn("Conformité assureur", r["blocs"])


class Scenarios(unittest.TestCase):
    def dicts(self, *paires):
        return [Constat("Exposition", niv, "t", "e", cle=cle).en_dict() for cle, niv in paires]

    def test_mail_usurpable_declenche_faux_fournisseur(self):
        s = scenarios.scenarios_pour(self.dicts(("dmarc", CRITIQUE)))
        self.assertTrue(any("fausse facture" in x["titre"].lower() for x in s))

    def test_rien_trouve_aucun_scenario(self):
        self.assertEqual(scenarios.scenarios_pour(self.dicts(("spf", OK), ("dmarc", OK))), [])

    def test_domaine_imitateur_declenche_hameconnage(self):
        s = scenarios.scenarios_pour(self.dicts(("domaines_imitateurs", INFO)))
        titres = " ".join(x["titre"].lower() for x in s)
        self.assertIn("imite le vôtre", titres)

    def test_scenarios_dans_le_rapport(self):
        reseau.dns = faux_dns({("ex.fr", "A"): ["203.0.113.5"]})  # pas de SPF/DMARC → usurpable
        r = cli.lancer(Cible("ex.fr", "Essai"), ["mail"], date="2026-11-20")
        self.assertTrue(r["scenarios"])
        self.assertIn("escroc pourrait faire", rapport.en_html(r))

    def setUp(self):
        self._dns = reseau.dns

    def tearDown(self):
        reseau.dns = self._dns


class Ensemble(Base):
    def test_note(self):
        self.assertEqual(note([]), 100)
        self.assertEqual(note([Constat("x", CRITIQUE, "t", "e")] * 5), 0)

    def test_note_globale_est_celle_du_pire_bloc(self):
        constats = [
            Constat("Exposition", INFO, "a", "a"),                 # bloc à 98
            Constat("Conformité assureur", CRITIQUE, "b", "b"),    # bloc à 75
            Constat("Conformité assureur", IMPORTANT, "c", "c"),
        ]
        r = rapport.construire("S", "ex.fr", "2026-11-20", constats, {}, [], None)
        self.assertEqual(r["blocs"]["Exposition"]["note"], 98)
        self.assertEqual(r["blocs"]["Conformité assureur"]["note"], 65)
        # la globale suit le maillon faible, jamais en dessous
        self.assertEqual(r["note_globale"], 65)

    def test_diagnostic_complet_et_fichiers(self):
        reseau.dns = faux_dns(SITE_SEUL)
        self.site_propre()
        resultat = cli.lancer(CIBLE, ["mail", "site"], date="2026-11-20")
        self.assertEqual(resultat["note_globale"], 46)  # 2 critiques, 2 infos
        with tempfile.TemporaryDirectory() as dossier:
            chemins = rapport.ecrire(resultat, dossier)
            with open(chemins["rapport.html"], encoding="utf-8") as fichier:
                page = fichier.read()
        self.assertIn("Société &lt;Test&gt;", page)   # le nom est bien neutralisé
        self.assertIn("DMARC absent", page)

    def test_deux_documents_executif_et_technique(self):
        reseau.dns = faux_dns(SITE_SEUL)
        self.site_propre()
        resultat = cli.lancer(CIBLE, ["mail", "site"], date="2026-11-20")
        with tempfile.TemporaryDirectory() as dossier:
            chemins = rapport.ecrire(resultat, dossier)
            self.assertIn("rapport-executif.html", chemins)
            with open(chemins["rapport-executif.html"], encoding="utf-8") as f:
                executif = f.read()
            with open(chemins["rapport.html"], encoding="utf-8") as f:
                technique = f.read()
        # l'exécutif renvoie au technique et n'affiche aucune carte de détail
        self.assertIn("rapport technique", executif)
        self.assertIn('class="suite"', executif)
        self.assertNotIn('class="constat', executif)
        # le technique détaille chaque constat
        self.assertIn('class="constat', technique)
        self.assertIn("DMARC absent", technique)

    def test_reseau_coupe(self):
        reseau.dns = reseau_coupe
        resultat = cli.lancer(CIBLE, ["mail", "site"])
        self.assertEqual(len(resultat["non_realises"]), 2)
        self.assertEqual(resultat["blocs"], {})

    def test_module_actif_refuse_sans_autorisation(self):
        MODULES["essai_actif"] = {"fonction": lambda c: ([], {}), "bloc": "Exposition",
                                  "actif": True, "defaut": False, "nom": "Scan d'essai"}
        try:
            resultat = cli.lancer(CIBLE, ["essai_actif"])
            self.assertIn("autorisation", resultat["non_realises"][0]["raison"].lower())
            with tempfile.NamedTemporaryFile(suffix=".pdf") as papier:
                papier.write(b"autorisation signee")
                papier.flush()
                resultat = cli.lancer(CIBLE, ["essai_actif"], papier.name)
            self.assertEqual(resultat["non_realises"], [])
            self.assertEqual(len(resultat["autorisation"]["empreinte_sha256"]), 64)
        finally:
            del MODULES["essai_actif"]

    def test_domaine_invalide(self):
        self.assertEqual(cli.nettoyer_domaine("https://Ex.FR/page"), "ex.fr")
        with self.assertRaises(ValueError):
            cli.nettoyer_domaine("pas un domaine")
        with self.assertRaises(autorisation.AutorisationManquante):
            autorisation.verifier(None)


class Comparaison(Base):
    CHECKDMARC = json.dumps({
        "domain": "ex.fr", "dnssec": False,
        "spf": {"record": "v=spf1 include:_spf.google.com -all", "valid": True},
        "dmarc": {"record": "v=DMARC1; p=none", "tags": {"p": {"value": "none"}}},
        "mta_sts": {"valid": False}, "smtp_tls_reporting": {"valid": False},
    })

    def test_recoupe_et_unique(self):
        # mail (natif) et checkdmarc sur le même domaine : qui trouve quoi ?
        reseau.dns = faux_dns({
            ("ex.fr", "MX"): ["10 mx.ex.fr."],
            ("ex.fr", "TXT"): ["v=spf1 include:_spf.google.com -all"],
            ("_dmarc.ex.fr", "TXT"): ["v=DMARC1; p=none"]})
        outils.executer = lambda *a, **k: self.CHECKDMARC
        comp = comparaison.comparer(Cible("ex.fr", "Essai"), ["mail", "checkdmarc"])
        par_facette = {l["facette"]: l for l in comp["lignes"]}
        # SPF et DMARC : vus par les DEUX outils -> recoupés
        self.assertEqual(par_facette["spf"]["statut"], "recoupé")
        self.assertEqual(len(par_facette["dmarc"]["par"]), 2)
        # MTA-STS et DNSSEC : apportés UNIQUEMENT par checkdmarc
        self.assertEqual(par_facette["mta_sts"]["statut"], "unique")
        self.assertIn("mta_sts", par_facette)
        self.assertIn("dnssec", par_facette)
        # DKIM : apporté uniquement par le module natif
        self.assertEqual(par_facette["dkim"]["par"], ["Réglages mail (usurpation)"])
        # le rendu HTML se construit sans erreur
        self.assertIn("Ce que chaque outil apporte", comparaison.en_html(comp))

    def test_comparaison_sans_reseau(self):
        reseau.dns = reseau_coupe
        outils.executer = lambda *a, **k: self.CHECKDMARC.replace('"valid": True', '"valid": False')
        comp = comparaison.comparer(Cible("ex.fr"), ["mail"])
        self.assertEqual(len(comp["non_realises"]), 1)  # mail non réalisé, pas de faux constat


class Interface(Base):
    def demarrer(self, sortie, code=""):
        serveur = ThreadingHTTPServer(("127.0.0.1", 0), interface.fabrique(sortie, code))
        threading.Thread(target=serveur.serve_forever, daemon=True).start()
        self.addCleanup(serveur.shutdown)
        self.addCleanup(serveur.server_close)
        return f"http://127.0.0.1:{serveur.server_address[1]}"

    def test_formulaire_puis_rapport(self):
        reseau.dns = faux_dns(BON_DNS)
        self.site_propre()
        outils.executer = lambda *a, **k: "[]"   # dnstwist : aucun imitateur, sans réseau
        with tempfile.TemporaryDirectory() as sortie:
            base = self.demarrer(sortie)
            accueil = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("Nouveau diagnostic", accueil)
            reponse = urllib.request.urlopen(base + "/diagnostic",
                                             data=b"domaine=ex.fr&societe=Essai")
            page = reponse.read().decode()
            self.assertIn("/rapport/ex_fr_", reponse.geturl())
            self.assertIn("100<small>", page)
            with self.assertRaises(urllib.error.HTTPError) as refus:
                urllib.request.urlopen(base + "/diagnostic", data=b"domaine=%3Bls")
            self.assertEqual(refus.exception.code, 400)
            with self.assertRaises(urllib.error.HTTPError) as absent:
                urllib.request.urlopen(base + "/rapport/..%2F..%2Fetc")
            self.assertEqual(absent.exception.code, 404)

    def test_code_obligatoire_en_reseau_local(self):
        with tempfile.TemporaryDirectory() as sortie:
            base = self.demarrer(sortie, code="secret123")
            with self.assertRaises(urllib.error.HTTPError) as refus:
                urllib.request.urlopen(base + "/")
            self.assertEqual(refus.exception.code, 403)
            ouvreur = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
            page = ouvreur.open(base + "/?code=secret123").read().decode()
            self.assertIn("Nouveau diagnostic", page)


class Banc(unittest.TestCase):
    SORTIES = {
        "subfinder": "www.cible.fr mail.cible.fr vpn.cible.fr",
        "amass": "www.cible.fr mail.cible.fr vpn.cible.fr old.cible.fr",
        "dnsx": "www.cible.fr test.cible.fr preprod.cible.fr",
        "assetfinder": "www.cible.fr mail.cible.fr",
    }

    def test_extraction_par_facette(self):
        self.assertEqual(banc.extraire("a@cible.fr et b@autre.com", "mails"),
                         {"a@cible.fr", "b@autre.com"})
        self.assertEqual(banc.extraire("CVE-2024-3400 et cve-2023-1234", "failles"),
                         {"cve-2024-3400", "cve-2023-1234"})
        self.assertEqual(banc.extraire("serveur 10.0.0.4 et 999.1.1.1", "ip"), {"10.0.0.4"})

    def test_le_bruit_n_est_pas_un_domaine(self):
        # une sortie d'outil contient des noms de fichiers : ils ne doivent pas compter
        self.assertEqual(banc.extraire("resultat.json config.yaml vrai.cible.fr", "domaines"),
                         {"vrai.cible.fr"})

    def test_un_message_d_erreur_ne_compte_pas_comme_trouvaille(self):
        # cas réel : dnsrecon échoue et affiche la cible dans son erreur.
        erreur = "[*] std: Performing General Enumeration against: github.io...\n" \
                 "[-] Could not resolve domain: github.io"
        self.assertEqual(banc.extraire(erreur, "domaines", exclure=["github.io"]), set())
        # sans exclusion, la cible remonterait à tort
        self.assertIn("github.io", banc.extraire(erreur, "domaines"))

    def test_la_cible_est_ecartee_des_trouvailles(self):
        mesure = banc.mesurer({"o": "cible.fr www.cible.fr"}, "domaines", exclure=["cible.fr"])
        self.assertEqual(mesure["union"], {"www.cible.fr"})

    def test_facette_inconnue_refusee(self):
        with self.assertRaises(ValueError):
            banc.extraire("texte", "licornes")

    def test_apport_propre_de_chaque_outil(self):
        mesure = banc.mesurer(self.SORTIES, "domaines")
        self.assertEqual(len(mesure["union"]), 6)
        self.assertEqual(mesure["uniques"]["amass"], {"old.cible.fr"})
        self.assertEqual(mesure["uniques"]["dnsx"], {"test.cible.fr", "preprod.cible.fr"})
        self.assertEqual(mesure["uniques"]["subfinder"], set())   # tout est déjà chez amass

    def test_meilleur_melange_couvre_tout_et_ecarte_les_inutiles(self):
        mesure = banc.mesurer(self.SORTIES, "domaines")
        melange = banc.meilleur_melange(mesure)
        retenus = {etape["outil"] for etape in melange["melange"]}
        self.assertEqual(retenus, {"amass", "dnsx"})
        self.assertEqual(melange["inutiles"], ["assetfinder", "subfinder"])
        self.assertEqual(melange["non_couvert"], [])
        couvert = set().union(*(mesure["par_outil"][nom] for nom in retenus))
        self.assertEqual(couvert, mesure["union"])

    def test_un_seul_outil(self):
        mesure = banc.mesurer({"seul": "a.cible.fr b.cible.fr"}, "domaines")
        melange = banc.meilleur_melange(mesure)
        self.assertEqual([e["outil"] for e in melange["melange"]], ["seul"])
        self.assertEqual(melange["inutiles"], [])


class Decouverte(unittest.TestCase):
    # Aide réelle de dnstwist : la cible est positionnelle, et « -d » est un dictionnaire.
    AIDE_DNSTWIST = ("usage: dnstwist [OPTION]... DOMAIN\n"
                     "  -d, --dictionary FILE  Generate more domains using dictionary FILE\n"
                     "  -f, --format FORMAT    Output format\n")
    AIDE_DRAPEAU = ("Usage of subfinder:\n"
                    "  -d, --domain string   domain to find subdomains for\n"
                    "  -silent               show only results\n")

    def test_drapeau_qui_attend_un_fichier_nest_pas_la_cible(self):
        proposition = decouverte.proposer("dnstwist", self.AIDE_DNSTWIST)
        self.assertEqual(proposition["arguments"], ["{cible}"])   # et surtout pas ["-d", "{cible}"]
        self.assertNotIn("-d", proposition["arguments"])
        self.assertEqual(proposition["confiance"], "bonne")

    def test_drapeau_de_cible_reconnu(self):
        proposition = decouverte.proposer("subfinder", self.AIDE_DRAPEAU)
        self.assertIn("{cible}", proposition["arguments"])
        self.assertTrue({"-d", "--domain"} & set(proposition["arguments"]))
        self.assertIn("-silent", proposition["arguments"])        # sortie propre
        self.assertEqual(proposition["confiance"], "bonne")

    # Aides réelles, relevées sur la machine.
    AIDE_SHERLOCK = ("usage: sherlock [-h] [--version] [--verbose] [--no-color]\n"
                     "                [--timeout TIMEOUT] USERNAMES [USERNAMES ...]\n\n"
                     "  --verbose, -v, -d, --debug   Display debugging information\n")
    AIDE_DNSRECON = ("usage: dnsrecon [-h] [-d DOMAIN] [-n NS_SERVER] [-D DICTIONARY]\n"
                     "                [--threads THREADS]\n\n"
                     "  -d DOMAIN, --domain DOMAIN   Target domain.\n")

    def test_drapeau_synonyme_de_debug_nest_pas_la_cible(self):
        proposition = decouverte.proposer("sherlock", self.AIDE_SHERLOCK)
        self.assertNotIn("-d", proposition["arguments"])      # -d y est un synonyme de --debug
        self.assertEqual(proposition["arguments"], ["--no-color", "{cible}"])
        self.assertEqual(proposition["confiance"], "bonne")

    def test_cible_entre_crochets_est_un_drapeau_pas_un_positionnel(self):
        # « [-d DOMAIN] » décrit une option : la cible n'est PAS positionnelle ici
        proposition = decouverte.proposer("dnsrecon", self.AIDE_DNSRECON)
        self.assertIn("{cible}", proposition["arguments"])
        self.assertTrue({"-d", "--domain"} & set(proposition["arguments"]))

    def test_sans_aide_la_confiance_est_nulle(self):
        proposition = decouverte.proposer("mystere", "")
        self.assertEqual(proposition["confiance"], "nulle")
        self.assertEqual(proposition["arguments"], [])

    def test_aide_sans_indice_reste_une_supposition(self):
        proposition = decouverte.proposer("opaque", "Ce programme fait des choses.\n")
        self.assertEqual(proposition["confiance"], "faible")
        self.assertIn("supposée", proposition["indices"])


class Lanceur(unittest.TestCase):
    def test_outils_par_facette(self):
        domaines = lanceur.pour_facette("domaines")
        self.assertIn("subfinder", domaines)
        self.assertIn("amass", domaines)
        self.assertNotIn("whatweb", domaines)        # whatweb répond aux urls
        self.assertEqual(lanceur.pour_facette("licornes"), [])

    def test_outil_non_declare_ecarte_sans_erreur(self):
        resultat = lanceur.lancer_un("outil-qui-nexiste-pas", "ex.fr")
        self.assertFalse(resultat["lance"])
        self.assertEqual(resultat["raison"], "non déclaré")

    def test_outil_absent_ecarte_sans_erreur(self):
        vrai = lanceur.shutil.which
        lanceur.shutil.which = lambda nom: None
        try:
            resultat = lanceur.lancer_un("subfinder", "ex.fr")
        finally:
            lanceur.shutil.which = vrai
        self.assertFalse(resultat["lance"])
        self.assertEqual(resultat["raison"], "pas installé")

    def test_la_cible_est_bien_substituee(self):
        ligne = lanceur.LANCEMENTS["subfinder"]
        arguments = [a.replace("{cible}", "cible.fr") for a in ligne["arguments"]]
        self.assertIn("cible.fr", arguments)
        self.assertNotIn("{cible}", " ".join(arguments))

    def test_outil_sans_resultat_est_marque_echoue(self):
        lanceur.LANCEMENTS["vide-essai"] = {"commande": "true", "arguments": [],
                                            "facettes": ["domaines"]}
        try:
            resultat = lanceur.lancer_un("vide-essai", "cible.fr")
        finally:
            del lanceur.LANCEMENTS["vide-essai"]
        self.assertTrue(resultat["lance"])
        self.assertTrue(resultat["echoue"])     # lancé, mais n'a rien produit

    def test_lancement_reel_et_ecriture_des_sorties(self):
        # on déclare un faux outil qui existe partout, pour vérifier la mécanique
        lanceur.LANCEMENTS["echo-essai"] = {"commande": "echo",
                                            "arguments": ["a.{cible} b.{cible}"],
                                            "facettes": ["domaines"]}
        try:
            with tempfile.TemporaryDirectory() as dossier:
                comptes = lanceur.lancer_tous(["echo-essai"], "cible.fr", dossier,
                                              journal=lambda *a: None)
                self.assertTrue(comptes[0]["lance"])
                with open(os.path.join(dossier, "echo-essai.txt"), encoding="utf-8") as f:
                    self.assertIn("a.cible.fr", f.read())
            self.assertIn("echo-essai", lanceur.temps_par_outil(comptes))
        finally:
            del lanceur.LANCEMENTS["echo-essai"]


class Installeur(unittest.TestCase):
    def test_lecture_du_depot(self):
        self.assertEqual(installeur.depot("https://github.com/soxoj/maigret"), ("soxoj", "maigret"))
        self.assertEqual(installeur.depot("https://github.com/a/b.git"), ("a", "b"))
        self.assertIsNone(installeur.depot("https://exemple.fr/outil"))

    def test_methodes_essayees_dans_l_ordre(self):
        outil = {"nom": "Maigret", "lien": "https://github.com/soxoj/maigret"}
        libelles = [libelle for libelle, _ in installeur.methodes(outil)]
        self.assertEqual(libelles, ["pipx (PyPI)", "pipx (dépôt)", "go", "npm"])
        self.assertEqual(installeur.methodes({"nom": "X", "lien": ""}), [])

    def test_a_blanc_n_installe_rien(self):
        outil = {"nom": "Maigret", "lien": "https://github.com/soxoj/maigret"}
        resultat = installeur.installer_un(outil, a_blanc=True)
        self.assertFalse(resultat["installe"])
        self.assertIn("pipx install maigret", resultat["raison"])

    def test_catalogue_complet_et_categorise(self):
        outils_catalogue = installeur.charger()
        self.assertEqual(len(outils_catalogue), 222)
        self.assertEqual(sum(installeur.categories(outils_catalogue).values()), 222)

    def test_resume_compte_par_methode(self):
        comptes = [{"nom": "a", "installe": True, "methode": "pipx (PyPI)", "raison": ""},
                   {"nom": "b", "installe": True, "methode": "pipx (PyPI)", "raison": ""},
                   {"nom": "c", "installe": False, "methode": "", "raison": "cassé"}]
        bilan = installeur.resume(comptes)
        self.assertEqual((bilan["total"], bilan["installes"], bilan["echecs"]), (3, 2, 1))
        self.assertEqual(bilan["par_methode"], {"pipx (PyPI)": 2})


class Pdf(unittest.TestCase):
    def test_sans_navigateur_message_clair(self):
        vrai = pdf.trouver_navigateur
        pdf.trouver_navigateur = lambda: None
        try:
            with self.assertRaises(pdf.PasDeNavigateur) as absence:
                pdf.html_vers_pdf("peu importe.html", "sortie.pdf")
            self.assertIn("Ctrl+P", str(absence.exception))
        finally:
            pdf.trouver_navigateur = vrai

    def test_conversion_reelle_si_navigateur_present(self):
        if not pdf.trouver_navigateur():
            self.skipTest("aucun navigateur Chromium sur cette machine")
        with tempfile.TemporaryDirectory() as dossier:
            html = os.path.join(dossier, "p.html")
            with open(html, "w", encoding="utf-8") as fichier:
                fichier.write("<!DOCTYPE html><html><body><h1>Vigie</h1></body></html>")
            sortie = pdf.html_vers_pdf(html, os.path.join(dossier, "p.pdf"))
            with open(sortie, "rb") as fichier:
                self.assertTrue(fichier.read(5).startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
