"""Essais sans internet : on remplace le réseau par des réponses préparées.

    python3 -m unittest discover -s tests
"""
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigie import (autorisation, banc, cli, comparaison, decouverte,  # noqa: E402
                   installeur,
                   lanceur,
                   interface, outils, pdf, rapport, reseau, scenarios)
from vigie.modeles import (CRITIQUE, IMPORTANT, INFO, OK, Cible, Constat,  # noqa: E402
                           ControleImpossible, fusionner, note)
from vigie.modules import MODULES, PAR_DEFAUT, conformite, domaines, mail, pseudos, site  # noqa: E402
from vigie.modules import (adresses, apercu, archives, chiffrement, metadonnees,  # noqa: E402
                           qualite_site, sousdomaines, technos)

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


def pas_de_telechargement(*a, **k):
    raise OSError("pas d'internet pendant les essais")


def resultat(sortie="", erreurs="", code=0):
    """Ce que renvoie outils.executer_detail : code de retour, sortie, messages d'erreur."""
    return subprocess.CompletedProcess(["outil"], code, sortie, erreurs)


class Base(unittest.TestCase):
    def setUp(self):
        # Aucun essai ne se connecte pour de vrai : la vérification HTTPS de Vigie répond
        # « on ne sait pas », sauf si l'essai dit autre chose.
        self._sauve_https = reseau.https_repond
        reseau.https_repond = lambda *a, **k: reseau.INCONNU
        self.addCleanup(setattr, reseau, "https_repond", self._sauve_https)
        # La Wayback Machine n'est jamais interrogée pour de vrai : « rien d'archivé ».
        self.addCleanup(setattr, archives, "wayback", archives.wayback)
        archives.wayback = lambda domaine: []
        self._sauve = (reseau.dns, site._ouvrir, site._jours_certificat, outils.executer,
                       metadonnees._ouvrir)
        # Aucun essai ne télécharge pour de vrai, et aucun résultat d'un essai ne
        # resserre dans le suivant (les modules gardent 10 minutes ce qu'ils ont trouvé).
        metadonnees._ouvrir = pas_de_telechargement
        from vigie.modules import telephone
        self._sauve_tel = telephone._ouvrir
        telephone._ouvrir = pas_de_telechargement
        from vigie.modules import bibliotheques
        self._sauve_bib = bibliotheques._ouvrir
        bibliotheques._ouvrir = pas_de_telechargement
        sousdomaines._CACHE.clear()
        archives._CACHE.clear()
        from vigie import indices
        self._sauve_indices = (indices._ouvrir, outils.executer_detail)
        indices._ouvrir = pas_de_telechargement
        indices.oublier()

    def tearDown(self):
        (reseau.dns, site._ouvrir, site._jours_certificat, outils.executer,
         metadonnees._ouvrir) = self._sauve
        from vigie import indices
        indices._ouvrir, outils.executer_detail = self._sauve_indices
        indices.oublier()
        from vigie.modules import telephone
        telephone._ouvrir = self._sauve_tel
        from vigie.modules import bibliotheques
        bibliotheques._ouvrir = self._sauve_bib

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

    def test_conseil_rapports_dmarc_survit_a_la_fusion(self):
        # Vrai diagnostic du 21/11/2026 : « pas d'adresse de rapport » disparaissait,
        # fondu dans la politique DMARC (même clé), et « quarantaine » aussi.
        table = dict(BON_DNS)
        table[("_dmarc.ex.fr", "TXT")] = ["v=DMARC1; p=quarantine"]
        _, constats = self.niveaux(table)
        titres = [c.titre for c in fusionner(constats)]
        self.assertIn("DMARC en quarantaine", titres)
        self.assertIn("Pas d'adresse de rapport DMARC", titres)


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

    def test_base_de_fuites_ecartee(self):
        sortie = self.SORTIE + "[+] HudsonRock: https://cavalier.hudsonrock.com/x?username=jdupont\n"
        self.assertEqual([c["site"] for c in pseudos.lire_sortie(sortie)], ["GitHub", "Reddit"])

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

        def faux(nom, arguments, delai=0, dossier=None, partiel=False):
            appels.append((nom, arguments))
            return self.SORTIE
        outils.executer = faux
        vrai = outils.disponible
        outils.disponible = lambda nom: nom == "sherlock"     # Sherlock seul
        try:
            constats, brut = pseudos.analyser(Cible("ex.fr", pseudos=["jdupont"],
                                                    accord_dirigeant=True))
        finally:
            outils.disponible = vrai
        self.assertEqual(appels[0][0], "sherlock")
        self.assertEqual(appels[0][1][0], "jdupont")
        self.assertIn("2 comptes publics probables", constats[0].titre)
        self.assertEqual(len(brut["jdupont"]["sites"]), 2)

    def test_recoupement_entre_outils(self):
        # Comme sur « vigie » le 21/11/2026 : chaque outil voit des sites que les autres ratent.
        sites = pseudos.recouper({
            "Sherlock": [{"site": "GitHub", "adresse": "a"}, {"site": "Steam Community (User)",
                                                             "adresse": "b"}],
            "Maigret": [{"site": "GitHub", "adresse": "a"}, {"site": "Facebook", "adresse": "c"}],
            "user-scanner": [{"site": "github", "adresse": "a"}, {"site": "Instagram", "adresse": "d"}]})
        self.assertEqual(len(sites["github"]["vu_par"]), 3)
        self.assertEqual(sites["facebook"]["vu_par"], ["Maigret"])
        self.assertEqual(pseudos.lire_user_scanner([
            {"status": "Found", "site_name": "Instagram.creator", "url": "u"},
            {"status": "Not Found", "site_name": "X", "url": "v"},
            {"status": "Found", "site_name": "HudsonRock", "url": "w"}]),
            [{"site": "Instagram", "adresse": "u"}])

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
        outils.executer_detail = lambda *a, **k: resultat(self.SORTIE)
        constats, _ = domaines.analyser(CIBLE)
        self.assertEqual(constats[0].niveau, IMPORTANT)
        self.assertIn("2 domaines", constats[0].titre)

    def test_aucun_imitateur(self):
        outils.executer_detail = lambda *a, **k: resultat("[]")
        constats, _ = domaines.analyser(CIBLE)
        self.assertEqual(constats[0].niveau, OK)

    def test_resolveurs_publics_et_domaine_en_dernier(self):
        # Essai réel du 21/11/2026 : par la box, plus de 10 minutes ; en public, 13 secondes.
        args = domaines.arguments("ex.fr")
        self.assertEqual(args[-1], "ex.fr")
        self.assertEqual(args[args.index("--nameservers") + 1], ",".join(reseau.SERVEURS_DNS))

    def test_sans_module_dns_relance_sur_le_dns_de_la_machine(self):
        # Vraie cause du 24/11/2026 : dnstwist posé sans dnspython refuse --nameservers
        # et s'arrête en 0 s (code 2). Vigie le relance sans cette option.
        appels = []

        def faux(nom, arguments, **k):
            appels.append(arguments)
            if "--nameservers" in arguments:
                return resultat("", "usage: dnstwist ...\ndnstwist: error: missing DNSPython "
                                    "library\n", 2)
            return resultat(self.SORTIE)
        outils.executer_detail = faux
        constats, brut = domaines.analyser(CIBLE)
        self.assertEqual(len(appels), 2)
        self.assertNotIn("--nameservers", appels[1])
        self.assertIn("2 domaines", constats[0].titre)
        self.assertIn("sans module DNS", brut["note"])

    def test_aucune_reponse_dns_n_est_pas_aucun_imitateur(self):
        # Avec --registered, une sortie vide = pas même le domaine de la société n'a
        # répondu : c'est le DNS qui coince, pas « aucun imitateur ».
        outils.executer_detail = lambda *a, **k: resultat("")
        with self.assertRaises(ControleImpossible) as empechement:
            domaines.analyser(CIBLE)
        self.assertIn("aucune réponse DNS", str(empechement.exception))

    def test_erreur_expliquee_en_francais(self):
        outils.executer_detail = lambda *a, **k: resultat(
            "", "Traceback (most recent call last):\nModuleNotFoundError: No module named 'x'", 1)
        with self.assertRaises(ControleImpossible) as empechement:
            domaines.analyser(CIBLE)
        self.assertIn("réinstaller", str(empechement.exception))


class Catalogue(unittest.TestCase):
    def test_chaque_outil_appele_par_un_module_est_au_catalogue(self):
        # Cas réel du 21/11/2026 : checkdmarc était appelé mais absent du catalogue.
        import re
        dossier = os.path.join(os.path.dirname(__file__), "..", "vigie", "modules")
        for nom_fichier in os.listdir(dossier):
            if nom_fichier.endswith(".py"):
                with open(os.path.join(dossier, nom_fichier), encoding="utf-8") as fichier:
                    for outil in re.findall(r'outils\.executer\(\s*"([^"]+)"', fichier.read()):
                        self.assertIn(outil, outils.CATALOGUE, f"{nom_fichier} appelle {outil}")

    def test_checkdmarc_remarques_ptr_et_pct(self):
        from vigie.modules import checkdmarc_mod
        data = {"spf": {"record": "v=spf1 include:mx.ovh.com -all", "warnings": [
                    "Error when processing mail-out.ovh.net: The ptr mechanism should not be used"]},
                "dmarc": {"record": "v=DMARC1; p=quarantine; pct=100", "warnings": [
                    "Support for the pct tag was removed"], "tags": {"p": {"value": "quarantine"}}}}
        cles = {c.cle: c for c in checkdmarc_mod._avertissements(data)}
        self.assertTrue(cles["spf_ptr"].hors_note and cles["dmarc_pct"].hors_note)
        self.assertEqual(checkdmarc_mod._avertissements({}), [])

    def test_checkdmarc_domaine_avant_les_resolveurs(self):
        from vigie.modules import checkdmarc_mod
        args = checkdmarc_mod.arguments("ex.fr")
        self.assertEqual(args[0], "ex.fr")  # -n avale tout ce qui le suit
        self.assertEqual(args[args.index("-n") + 1:], reseau.SERVEURS_DNS)


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
        outils.executer_detail = lambda *a, **k: resultat("[]")
        with tempfile.TemporaryDirectory() as sortie:
            base = self.demarrer(sortie)
            accueil = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("Nouveau diagnostic", accueil)
            reponse = urllib.request.urlopen(base + "/diagnostic",
                                             data=b"domaine=ex.fr&societe=Essai&formule=rapide")
            suivi = reponse.geturl()
            self.assertIn("/suivi/", suivi)
            self.assertIn("Diagnostic en cours", reponse.read().decode())
            for _ in range(100):  # le diagnostic tourne en arrière-plan
                etat = json.loads(urllib.request.urlopen(suivi + "/etat").read())
                if etat["etat"] != "en_cours":
                    break
                time.sleep(0.05)
            self.assertEqual(etat["etat"], "fini", etat)
            # Sans les vrais outils, leurs contrôles sont « non réalisés », jamais en échec.
            etats = {e["nom"]: e["etat"] for e in etat["etapes"]}
            self.assertEqual(list(etats), PAR_DEFAUT)
            self.assertTrue(set(etats.values()) <= {"fini", "non_realise"}, etats)
            self.assertEqual((etats["mail"], etats["site"], etats["domaines"]),
                             ("fini", "fini", "fini"))
            self.assertEqual(etat["etapes"][0]["libelle"], "Réglages mail (usurpation)")
            page = urllib.request.urlopen(base + "/rapport/" + etat["rapport"]).read().decode()
            self.assertTrue(etat["rapport"].startswith("ex_fr_"))
            self.assertIn("100<small>", page)
            with self.assertRaises(urllib.error.HTTPError) as refus:
                urllib.request.urlopen(base + "/diagnostic", data=b"domaine=%3Bls")
            self.assertEqual(refus.exception.code, 400)

    def test_chaque_page_a_le_retour_accueil(self):
        reseau.dns = faux_dns(BON_DNS)
        self.site_propre()
        outils.executer = lambda *a, **k: "[]"
        with tempfile.TemporaryDirectory() as sortie:
            base = self.demarrer(sortie)
            reponse = urllib.request.urlopen(base + "/diagnostic", data=b"domaine=ex.fr")
            suivi = reponse.geturl()
            for _ in range(100):
                etat = json.loads(urllib.request.urlopen(suivi + "/etat").read())
                if etat["etat"] != "en_cours":
                    break
                time.sleep(0.05)
            pages = ["/", "/outils-un", "/comparer", "/manuel", suivi[len(base):],
                     "/rapport/" + etat["rapport"]]
            for chemin in pages:
                texte = urllib.request.urlopen(base + chemin).read().decode()
                self.assertIn('class="vigie-accueil" href="/"', texte, chemin)
                self.assertEqual(texte.count('class="vigie-nav"'), 1, chemin)
            with self.assertRaises(urllib.error.HTTPError) as introuvable:
                urllib.request.urlopen(base + "/nexiste-pas")
            self.assertIn("vigie-accueil", introuvable.exception.read().decode())
            # Le rapport enregistré (celui qui part chez le client) reste sans la barre.
            with open(os.path.join(sortie, etat["rapport"], "rapport.html"), encoding="utf-8") as f:
                self.assertNotIn("vigie-nav", f.read())
            with self.assertRaises(urllib.error.HTTPError) as absent:
                urllib.request.urlopen(base + "/rapport/..%2F..%2Fetc")
            self.assertEqual(absent.exception.code, 404)

    def test_suivi_signale_echec_et_controle_impossible(self):
        def plante(cible):
            raise RuntimeError("outil introuvable")

        def impossible(cible):
            raise ControleImpossible("pas de réseau")

        modules = {"a": {"fonction": impossible, "actif": False, "nom": "Contrôle A"},
                   "b": {"fonction": plante, "actif": False, "nom": "Contrôle B"}}
        with mock.patch.dict(cli.MODULES, modules), \
                mock.patch.dict(interface.MODULES, modules), \
                tempfile.TemporaryDirectory() as sortie:
            ident = interface.nouveau_suivi(Cible("ex.fr"), ["a", "b"])
            interface.executer_suivi(ident, Cible("ex.fr"), ["a", "b"], sortie)
        etat = interface.etat_suivi(ident)
        # Depuis le diagnostic complet (24/11/2026) : un outil qui plante est noté en
        # échec, mais le diagnostic va au bout et produit son rapport.
        self.assertEqual(etat["etat"], "fini")
        self.assertEqual([e["etat"] for e in etat["etapes"]], ["non_realise", "echec"])
        self.assertEqual(etat["etapes"][0]["detail"], "pas de réseau")
        self.assertIn("outil introuvable", etat["etapes"][1]["detail"])

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
        essais = installeur.methodes(outil, install="pipx install maigret (ou pip3 install "
                                                    "maigret ; brew install maigret ; docker)")
        self.assertEqual([libelle for libelle, _ in essais],
                         ["brew (documenté)", "pipx (documenté)", "pipx (dépôt)"])
        self.assertEqual(installeur.methodes({"nom": "X", "lien": ""}), [])

    def test_jamais_un_paquet_choisi_sur_son_seul_nom(self):
        # Cas réel du 21/11/2026 : « npm install -g subfinder » a posé un téléchargeur de
        # sous-titres. Sans documentation, seul le dépôt exact de l'outil est essayé.
        outil = {"nom": "Subfinder", "lien": "https://github.com/projectdiscovery/subfinder"}
        commandes = [c for _, c in installeur.methodes(outil, install="")]
        self.assertEqual(commandes, [
            ["pipx", "install", "git+https://github.com/projectdiscovery/subfinder"],
            ["go", "install", "github.com/projectdiscovery/subfinder@latest"]])
        documente = installeur.methodes(outil, install=(
            "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest "
            "(ou brew install subfinder)"))
        self.assertEqual(documente[0], ("brew (documenté)", ["brew", "install", "subfinder"]))
        self.assertIn(("go (documenté)", ["go", "install",
                                          "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]),
                      documente)
        self.assertFalse(any(c[0] == "npm" for _, c in documente))
        # « pip install -r requirements.txt » n'est pas un nom de paquet
        self.assertEqual(len(installeur.methodes(outil, install="pip3 install -r req.txt")), 1)

    def test_binaire_go_lu_dans_le_module(self):
        commande = ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]
        self.assertEqual(installeur.binaires_poses("go (documenté)", "", "p", "subfinder", commande),
                         ["subfinder"])
        self.assertEqual(installeur.binaires_poses(
            "go (dépôt)", "", "s", "gowitness", ["go", "install", "github.com/s/gowitness@latest"]),
            ["gowitness"])

    def test_a_blanc_n_installe_rien(self):
        outil = {"nom": "Maigret", "lien": "https://github.com/soxoj/maigret"}
        resultat = installeur.installer_un(outil, a_blanc=True)
        self.assertFalse(resultat["installe"])
        self.assertIn("install maigret", resultat["raison"])  # commande documentée

    def test_catalogue_complet_et_categorise(self):
        outils_catalogue = installeur.charger()
        self.assertEqual(len(outils_catalogue), 222)
        self.assertEqual(sum(installeur.categories(outils_catalogue).values()), 222)

    def test_binaires_lus_dans_la_sortie_de_pipx(self):
        sortie = ("  installed package sherlock-project 0.15.0\n"
                  "  These apps are now globally available\n"
                  "    - sherlock\n    - sherlock-cli\ndone!\n")
        self.assertEqual(installeur.binaires_poses("pipx (PyPI)", sortie, "x", "sherlock-project"),
                         ["sherlock", "sherlock-cli"])
        self.assertEqual(installeur.binaires_poses("go", "", "projectdiscovery", "subfinder"),
                         ["subfinder"])

    def test_un_binaire_absent_ne_repond_pas(self):
        self.assertFalse(installeur.repond("outil-qui-nexiste-vraiment-pas"))

    def test_installe_mais_muet_nest_pas_pret(self):
        # une installation qui réussit mais dont le binaire ne démarre pas
        vrai_lancer, vrai_repond = installeur._lancer, installeur.repond
        installeur._lancer = lambda commande, delai=600: (True, "", "")
        installeur.repond = lambda binaire, delai=25: False
        try:
            resultat = installeur.installer_un({"nom": "Coquille",
                                                "lien": "https://github.com/x/coquille"})
        finally:
            installeur._lancer, installeur.repond = vrai_lancer, vrai_repond
        self.assertTrue(resultat["installe"])
        self.assertFalse(resultat["repond"])
        self.assertIn("ne démarre pas", resultat["raison"])

    def test_resume_distingue_prets_et_coquilles(self):
        comptes = [{"nom": "a", "installe": True, "repond": True, "methode": "go", "raison": ""},
                   {"nom": "b", "installe": True, "repond": False, "methode": "go", "raison": ""},
                   {"nom": "c", "installe": False, "repond": False, "methode": "", "raison": "x"}]
        bilan = installeur.resume(comptes)
        self.assertEqual((bilan["prets"], bilan["coquilles"], bilan["echecs"]), (1, 1, 1))

    def test_parallele_donne_le_meme_resultat_que_la_file(self):
        outils_essai = [{"nom": f"o{n}", "lien": f"https://github.com/x/o{n}"} for n in range(6)]
        vrai = installeur.installer_un
        installeur.installer_un = lambda outil, a_blanc=False: {
            "nom": outil["nom"], "installe": outil["nom"] != "o3",
            "methode": "pipx (PyPI)", "raison": ""}
        try:
            file = installeur.installer(outils_essai, journal=lambda *a: None, parallele=1)
            front = installeur.installer(outils_essai, journal=lambda *a: None, parallele=4)
        finally:
            installeur.installer_un = vrai
        # mêmes outils, mêmes verdicts — seul l'ordre d'arrivée peut changer
        self.assertEqual({c["nom"] for c in file}, {c["nom"] for c in front})
        self.assertEqual(installeur.resume(file), installeur.resume(front))
        self.assertEqual(len(front), 6)

    def test_a_blanc_reste_sequentiel(self):
        outils_essai = [{"nom": "a", "lien": "https://github.com/x/a"},
                        {"nom": "b", "lien": "https://github.com/x/b"}]
        comptes = installeur.installer(outils_essai, a_blanc=True,
                                       journal=lambda *a: None, parallele=8)
        self.assertEqual(len(comptes), 2)
        self.assertTrue(all(not c["installe"] for c in comptes))

    def test_resume_compte_par_methode(self):
        comptes = [{"nom": "a", "installe": True, "methode": "pipx (PyPI)", "raison": ""},
                   {"nom": "b", "installe": True, "methode": "pipx (PyPI)", "raison": ""},
                   {"nom": "c", "installe": False, "methode": "", "raison": "cassé"}]
        bilan = installeur.resume(comptes)
        self.assertEqual((bilan["total"], bilan["installes"], bilan["echecs"]), (3, 2, 1))
        self.assertEqual(bilan["par_methode"], {"pipx (PyPI)": 2})


def ecrit_fichier(option, contenu, sortie=""):
    """Faux outil qui écrit son résultat dans le fichier donné après `option`."""
    def faux(nom, arguments, delai=0, dossier=None):
        if not any(a == option or a.startswith(option + "=") for a in arguments):
            return ""   # un autre outil appelé en passant (tlsx...) : rien à écrire
        chemin = next(a.split("=", 1)[1] for a in arguments if a.startswith(option + "=")) \
            if option.startswith("--output-path") else arguments[arguments.index(option) + 1]
        with open(chemin + (".json" if option == "-f" else ""), "w", encoding="utf-8") as f:
            f.write(json.dumps(contenu))
        return sortie
    return faux


class LotDix(Base):
    """Les outils du premier lot, avec des sorties relevées sur pavillon-noir.tech le 21/11/2026."""
    HTTPX = "\n".join(json.dumps(d) for d in [
        {"input": "ex.fr", "url": "https://ex.fr", "status_code": 200, "title": "Accueil",
         "webserver": "Apache", "tech": ["Apache HTTP Server", "MySQL", "PHP:8.3", "WordPress"],
         "scheme": "https"},
        {"input": "www.ex.fr", "url": "https://www.ex.fr", "final_url": "https://ex.fr/",
         "status_code": 200, "title": "Accueil", "tech": ["WordPress"], "scheme": "https"},
        {"input": "test.ex.fr", "url": "http://test.ex.fr", "status_code": 200,
         "title": "Site de test", "tech": [], "scheme": "http"},
    ])

    def test_sous_domaines_jamais_un_tiers(self):
        sortie = "\n".join(json.dumps({"host": h}) for h in
                           ["www.ex.fr", "*.mail.ex.fr", "ex.fr.pirate.com", "autre.fr"])
        self.assertEqual(sousdomaines.lire_sortie(sortie, "ex.fr"), ["mail.ex.fr", "www.ex.fr"])

    def test_sous_domaines_seulement_www(self):
        outils.executer = lambda *a, **k: json.dumps({"host": "www.ex.fr"})
        constats, brut = sousdomaines.analyser(CIBLE)
        self.assertEqual(constats[0].niveau, OK)
        self.assertEqual(brut["sous_domaines"], ["www.ex.fr"])

    def test_technos_wordpress_versions_et_site_en_clair(self):
        outils.executer = lambda nom, *a, **k: (self.HTTPX if nom == "httpx"
                                                else json.dumps({"host": "test.ex.fr"}))
        constats, _ = technos.analyser(CIBLE)
        par_cle = {c.cle: c for c in constats}
        self.assertIn("WordPress", par_cle["cms"].titre)
        self.assertIn("PHP 8.3", par_cle["versions_visibles"].explication)
        self.assertIn("test.ex.fr", par_cle["sites_annexes"].explication)  # www = redirection
        # test.ex.fr : httpx ne l'a vu qu'en clair, la vérification de Vigie ne sait pas
        # trancher -> « à confirmer », hors note. Jamais « important » sur un seul avis.
        douteux = next(c for c in constats if "test.ex.fr" in c.titre)
        self.assertEqual((douteux.niveau, douteux.hors_note), (INFO, True))
        # Refus net, deux fois : là, c'est important.
        reseau.https_repond = lambda *a, **k: reseau.NON
        constats, _ = technos.analyser(CIBLE)
        self.assertTrue(any(c.niveau == IMPORTANT and "test.ex.fr" in c.titre for c in constats))
        # Vigie arrive à se connecter en chiffré : httpx s'est trompé, rien à signaler.
        reseau.https_repond = lambda *a, **k: reseau.OUI
        constats, brut = technos.analyser(CIBLE)
        self.assertFalse(any("test.ex.fr" in c.titre for c in constats))
        self.assertEqual(brut["https_recoupe"], {"test.ex.fr": reseau.OUI})

    def test_technos_redirection_vers_https_n_est_pas_en_clair(self):
        # Cas réel du 24/11/2026 : www vu en http par httpx, mais redirigé vers https.
        ligne = json.dumps({"input": "www.ex.fr", "url": "http://www.ex.fr",
                            "final_url": "https://ex.fr/", "scheme": "http", "tech": []})
        self.assertTrue(technos.lire_sortie(ligne)[0]["chiffre"])

    SSLYZE = {"server_scan_results": [{"connectivity_status": "COMPLETED", "scan_result": {
        "tls_1_0_cipher_suites": {"result": {"accepted_cipher_suites": []}},
        "tls_1_2_cipher_suites": {"result": {"accepted_cipher_suites": [
            {"cipher_suite": {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}}]}},
        "tls_1_3_cipher_suites": {"result": {"accepted_cipher_suites": []}},
        "certificate_info": {"result": {"certificate_deployments": [{
            "path_validation_results": [{"was_validation_successful": True}],
            "received_certificate_chain": [{"not_valid_after": "2027-02-09T21:13:35Z",
                                            "issuer": {"rfc4514_string":
                                                       "CN=YE2,O=Let's Encrypt,C=US"}}]}]}}}}]}

    def test_chiffrement_comme_sur_pavillon_noir(self):
        outils.executer = ecrit_fichier("--json_out", self.SSLYZE)
        constats, brut = chiffrement.analyser(CIBLE)
        par_cle = {c.cle: c for c in constats}
        self.assertEqual(par_cle["protocoles_anciens"].niveau, OK)
        self.assertEqual(par_cle["tls13"].niveau, INFO)          # TLS 1.3 absent
        self.assertIn("Let's Encrypt", par_cle["certificat"].explication)
        self.assertEqual(brut["chiffrement"]["versions"], ["TLS 1.2"])

    def test_chiffrement_depasse_et_site_injoignable(self):
        data = json.loads(json.dumps(self.SSLYZE))
        data["server_scan_results"][0]["scan_result"]["tls_1_0_cipher_suites"]["result"][
            "accepted_cipher_suites"] = [{"cipher_suite": {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}}]
        outils.executer = ecrit_fichier("--json_out", data)
        niveaux = {c.cle: c.niveau for c in chiffrement.analyser(CIBLE)[0]}
        self.assertEqual(niveaux["protocoles_anciens"], IMPORTANT)
        self.assertEqual(niveaux["chiffrements_faibles"], IMPORTANT)
        with self.assertRaises(ControleImpossible):
            chiffrement.lire_sortie({"server_scan_results": [
                {"connectivity_status": "ERROR"}]})

    def test_lighthouse_lit_le_detail_pas_la_note(self):
        # Le piège réel : score 1 (« réussi ») alors que la protection manque.
        audits = {nom: {"score": 1, "scoreDisplayMode": "informative", "details": {"items": [
            {"severity": "High", "description": "absent"}]}} for nom in qualite_site.PROTECTIONS}
        audits["is-on-https"] = {"score": 1}
        audits["largest-contentful-paint"] = {"numericValue": 5800}
        outils.executer = ecrit_fichier("--output-path", {"audits": audits, "categories": {}})
        constats, _ = qualite_site.analyser(CIBLE)
        cles = {c.cle for c in constats}
        self.assertTrue({"hsts", "csp", "cadre", "coop", "lenteur"} <= cles, cles)
        self.assertIn("5.8 secondes", next(c.titre for c in constats if c.cle == "lenteur"))

    def test_archives_fichier_sensible_et_documents(self):
        outils.executer = lambda *a, **k: "\n".join([
            "https://ex.fr/backup/base.sql", "https://ex.fr/tarifs.pdf", "https://ex.fr/",
            "https://autre.fr/secret.sql"])  # un tiers : ignoré
        constats, brut = archives.analyser(CIBLE)
        niveaux = {c.cle: c.niveau for c in constats}
        self.assertEqual(niveaux["archives_sensibles"], IMPORTANT)
        self.assertEqual(niveaux["archives_documents"], INFO)
        self.assertEqual(brut["archives"]["total"], 3)

    def test_archives_vides(self):
        outils.executer = lambda *a, **k: ""
        self.assertEqual(archives.analyser(CIBLE)[0][0].niveau, OK)

    def test_metadonnees_liens_du_domaine_seulement(self):
        page = ('<img src="/wp-content/a.jpg" srcset="/b-600.jpg 600w, /b-1200.jpg 1200w">'
                '<a href="https://ex.fr/doc/tarifs.pdf">t</a><img src="https://cdn.autre.fr/c.jpg">')
        liens = metadonnees.liens_fichiers(page, "https://ex.fr/", "ex.fr")
        self.assertEqual(len(liens), 4)
        self.assertFalse(any("autre.fr" in l for l in liens))
        # un lien file:// glissé dans la page ne fait jamais lire un fichier du Mac
        piege = '<a href="file://ex.fr/etc/passwd.pdf">x</a>'
        self.assertEqual(metadonnees.liens_fichiers(piege, "https://ex.fr/", "ex.fr"), [])

    def test_metadonnees_noms_comptes_jamais_gardes(self):
        sortie = json.dumps([
            {"SourceFile": "a.pdf", "PDF:Author": "Julie Martin", "PDF:Creator": "Microsoft Word"},
            {"SourceFile": "b.jpg", "EXIF:Artist": "julie martin", "EXIF:GPSLatitude": 48.8},
        ])
        resultat = metadonnees.lire_sortie(sortie)
        self.assertEqual((resultat["noms"], resultat["avec_gps"]), (1, 1))
        self.assertEqual(resultat["logiciels"], ["Microsoft Word"])  # Creator PDF = logiciel
        self.assertNotIn("Julie", json.dumps(resultat))

    def test_harvester_sans_source_de_fuite_et_sans_liste(self):
        self.assertFalse(set(adresses.SOURCES) & set(adresses.INTERDITES))
        appels = []
        faux = ecrit_fichier("-f", {"emails": ["contact@ex.fr", "jean.dupont@ex.fr",
                                               "autre@gmail.com"], "people": ["Jean Dupont"]})

        def espion(nom, arguments, **k):
            appels.append(arguments)
            return faux(nom, arguments, **k)
        outils.executer = espion
        constats, brut = adresses.analyser(CIBLE)
        sources = appels[0][appels[0].index("-b") + 1].split(",")
        self.assertFalse(set(sources) & set(adresses.INTERDITES))
        self.assertEqual(brut["adresses"]["adresses"], 2)       # gmail : pas la société
        self.assertNotIn("@", constats[0].titre + constats[0].explication)
        self.assertNotIn("dupont", json.dumps(brut).lower())

    def test_capture_dans_le_rapport_html(self):
        reseau.dns = faux_dns(BON_DNS)
        resultat = rapport.construire("S", "ex.fr", "2026-11-21", [], {
            "apercu": {"apercu": {"type": "image/jpeg", "image_base64": "QUJD"}}}, [], None)
        self.assertIn("data:image/jpeg;base64,QUJD", rapport.en_html(resultat))
        sans = rapport.construire("S", "ex.fr", "2026-11-21", [], {}, [], None)
        self.assertNotIn("<figure", rapport.en_html(sans))

    def test_wordpress_et_lenteur_ne_comptent_pas_dans_la_note(self):
        # Décision d'Anass du 21/11/2026 : utiles au dirigeant, mais pas des failles.
        outils.executer = lambda nom, *a, **k: self.HTTPX.splitlines()[0] if nom == "httpx" else ""
        constats, _ = technos.analyser(CIBLE)
        cms = next(c for c in constats if c.cle == "cms")
        self.assertTrue(cms.hors_note)
        self.assertEqual(note([cms]), 100)
        self.assertEqual(note([cms, Constat("Exposition", INFO, "t", "e")]), 98)
        resultat = rapport.construire("S", "ex.fr", "2026-11-21", [cms], {}, [], None)
        self.assertIn("ne compte pas dans la note", rapport.en_html(resultat))

    def test_outils_cherches_aussi_hors_du_path(self):
        self.assertIn(os.path.expanduser("~/go/bin"), outils.chemin_recherche())


class LotDeux(Base):
    LINKCHECKER = (
        "# LinkChecker CSV\n"
        "urlname;parentname;base;result;warningstring;infostring;valid;url\n"
        "https://ex.fr/services/;https://ex.fr/article/;;404 Not Found;;;False;x\n"
        "https://vieux-partenaire.fr/;https://ex.fr/;;ConnectionError: nodename nor servname "
        "provided;;;False;x\n"
        "https://ex.fr/;;;200 OK;;;True;x\n")

    def test_liens_casses_et_domaine_mort(self):
        from vigie.modules import liens
        outils.executer = lambda *a, **k: self.LINKCHECKER
        constats, brut = liens.analyser(CIBLE)
        par_cle = {c.cle: c for c in constats}
        self.assertEqual(par_cle["liens_domaines_morts"].niveau, IMPORTANT)
        self.assertIn("vieux-partenaire.fr", par_cle["liens_domaines_morts"].explication)
        self.assertTrue(par_cle["liens_casses"].hors_note)          # page perdue : pas une faille
        self.assertIn("ex.fr/services/", par_cle["liens_casses"].explication)

    def test_accessibilite(self):
        from vigie.modules import accessibilite
        outils.executer = lambda *a, **k: json.dumps([{"type": "error", "code": "x"},
                                                      {"type": "notice", "code": "y"}])
        if not pdf.trouver_navigateur():
            self.skipTest("pas de Chrome ici")
        constats, _ = accessibilite.analyser(CIBLE)
        self.assertIn("1 défaut d'accessibilité", constats[0].titre)
        self.assertTrue(constats[0].hors_note)
        outils.executer = lambda *a, **k: "[]"
        self.assertEqual(accessibilite.analyser(CIBLE)[0][0].niveau, OK)


class Personne(Base):
    def test_holehe_lecture_et_accord(self):
        from vigie.modules import comptes_mail
        sortie = ("[+] amazon.com\n[+] spotify.com\n[-] ebay.com\n"
                  "[+] Email used, [-] Email not used, [x] Rate limit\n")
        self.assertEqual(comptes_mail.lire_sortie(sortie), ["amazon.com", "spotify.com"])
        with self.assertRaises(ControleImpossible):
            comptes_mail.analyser(Cible("ex.fr", emails=["a@ex.fr"]))      # sans accord
        outils.executer = lambda *a, **k: sortie
        constats, _ = comptes_mail.analyser(Cible("ex.fr", emails=["a@ex.fr"], accord_dirigeant=True))
        self.assertIn("2 sites", constats[0].titre)

    def test_portables_publies_comptes_jamais_recopies(self):
        from vigie.modules import telephone
        self.assertEqual(telephone.portables("Tél 06 12 34 56 78 ou +33 7.98.76.54.32, "
                                             "fixe 01 23 45 67 89, ou 0612345678"),
                         {"0612345678", "0798765432"})
        vrai = telephone._ouvrir
        telephone._ouvrir = lambda url: "Appelez le 06 12 34 56 78"
        try:
            constats, brut = telephone.analyser_publics(CIBLE)
        finally:
            telephone._ouvrir = vrai
        self.assertIn("1 numéro de portable", constats[0].titre)
        self.assertNotIn("12 34", constats[0].explication + json.dumps(brut))

    def test_phoneinfoga(self):
        from vigie.modules import telephone
        sortie = ("Results for local\nLocal: 06 39 98 00 00\nE164: +33639980000\nCountry: FR\n"
                  "URL: https://www.google.com/search?q=site%3Afacebook.com+x\n")
        outils.executer = lambda *a, **k: sortie
        with self.assertRaises(ControleImpossible):
            telephone.analyser(Cible("ex.fr", telephones=["+33639980000"]))
        constats, brut = telephone.analyser(Cible("ex.fr", telephones=["+33639980000"],
                                                  accord_dirigeant=True))
        self.assertIn("portable", constats[0].titre)
        self.assertEqual(len(brut["+33639980000"]["recherches"]), 1)


class Poste(unittest.TestCase):
    def test_lectures(self):
        from vigie import poste
        self.assertEqual(poste.lire_clamav("/a/b.exe: Win.Trojan.X FOUND\n/a/c: OK\n"),
                         [("/a/b.exe", "Win.Trojan.X")])
        self.assertEqual(poste.lire_yara("SUSP_Just_EICAR /tmp/eicar.txt\n"),
                         [("/tmp/eicar.txt", "SUSP_Just_EICAR")])
        lynis = poste.lire_lynis("  Hardening index : 72 [####]\n  ! Pas de pare-feu\n")
        self.assertEqual((lynis["note"], lynis["alertes"]), (72, ["Pas de pare-feu"]))
        texte = poste.en_texte({"dossier": "/x", "clamav": [], "yara": [("/x/a", "R")],
                                "lynis": None})
        self.assertIn("ClamAV (virus courants) : rien trouvé", texte)
        self.assertIn("NE PAS les ouvrir", texte)

    def test_regles_thor_ecartees(self):
        from vigie import poste
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "yara"))
            for nom in ("apt_x.yar", "generic_anomalies.yar", "lisez.txt"):
                open(os.path.join(d, "yara", nom), "w").close()
            self.assertEqual([os.path.basename(r) for r in poste.regles_yara(d)], ["apt_x.yar"])


class Bibliotheques(Base):
    def test_scripts_du_site_et_failles(self):
        from vigie.modules import bibliotheques
        page = ('<script src="/wp-includes/js/jquery/jquery.min.js?ver=1.12.4"></script>'
                '<script src="https://cdn.pub.com/x.js"></script><script src="file://ex.fr/a.js">')
        self.assertEqual(bibliotheques.scripts(page, "https://ex.fr/", "ex.fr"),
                         ["https://ex.fr/wp-includes/js/jquery/jquery.min.js?ver=1.12.4"])
        trouvees = bibliotheques.lire_sortie({"data": [{"results": [
            {"component": "jquery", "version": "1.12.4",
             "vulnerabilities": [{"severity": "medium"}, {"severity": "high"}]}]}]})
        self.assertEqual(trouvees[0]["graves"], 1)

    def test_site_illisible(self):
        from vigie.modules import bibliotheques
        with self.assertRaises(ControleImpossible):
            bibliotheques.analyser(CIBLE)


class Duel(unittest.TestCase):
    def test_recommandations(self):
        from vigie import duel
        self.assertIn("Garder A", duel.recommander({"A": {1, 2}, "B": {1}}, {"A": 3, "B": 1}))
        self.assertIn("B n'apporte rien", duel.recommander({"A": {1, 2}, "B": {1}}, {}))
        texte = duel.recommander({"A": {1, 2}, "B": {2, 3}, "C": {2}}, {})
        self.assertIn("A et B", texte)
        self.assertIn("C n'apporte rien", texte)
        self.assertIn("Aucun outil ne trouve", duel.recommander({"A": set(), "B": set()},
                                                                {"A": 5, "B": 2}))

    def test_comparaison_cote_a_cote(self):
        from vigie import duel
        vrai = dict(duel.QUESTIONS)
        duel.QUESTIONS["essai"] = {"titre": "t", "besoin": "domaine", "candidats": {
            "Un": (None, lambda c, d: {"a.ex.fr", "b.ex.fr"}),
            "Deux": (None, lambda c, d: {"b.ex.fr", "c.ex.fr"}),
            "Casse": (None, lambda c, d: (_ for _ in ()).throw(ControleImpossible("hors ligne"))),
            "Absent": ("outil-qui-nexiste-pas", lambda c, d: set())}}
        try:
            r = duel.comparer("essai", {"domaine": "ex.fr"})
        finally:
            duel.QUESTIONS.clear()
            duel.QUESTIONS.update(vrai)
        self.assertEqual(r["communs"], ["b.ex.fr"])
        self.assertEqual(r["seuls"]["Un"], ["a.ex.fr"])
        self.assertEqual(r["outils"]["Casse"]["echec"], "hors ligne")
        self.assertEqual(r["outils"]["Absent"]["echec"], "pas installé")
        self.assertIn("Un et Deux", r["recommandation"])
        self.assertIn("✓", duel.en_html(r))
        with self.assertRaises(ValueError):
            duel.comparer("secrets", {"dossier": "/dossier/qui/nexiste/pas"})

    def test_page_comparer(self):
        from vigie import duel
        vrai = dict(duel.QUESTIONS)
        duel.QUESTIONS.clear()
        duel.QUESTIONS["essai"] = {"titre": "Question d'essai", "besoin": "domaine", "candidats": {
            "Un": (None, lambda c, d: {"x"}), "Deux": (None, lambda c, d: {"x", "y"})}}
        self.addCleanup(lambda: (duel.QUESTIONS.clear(), duel.QUESTIONS.update(vrai)))
        with tempfile.TemporaryDirectory() as d:
            serveur = ThreadingHTTPServer(("127.0.0.1", 0), interface.fabrique(d, ""))
            threading.Thread(target=serveur.serve_forever, daemon=True).start()
            self.addCleanup(serveur.shutdown)
            self.addCleanup(serveur.server_close)
            base = f"http://127.0.0.1:{serveur.server_address[1]}"
            self.assertIn("Question d&#x27;essai", urllib.request.urlopen(base + "/comparer").read().decode())
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(base + "/comparer", data=b"question=essai")  # pas de domaine
            reponse = urllib.request.urlopen(base + "/comparer", data=b"question=essai&domaine=ex.fr")
            for _ in range(100):
                texte = urllib.request.urlopen(reponse.geturl()).read().decode()
                if "en cours" not in texte:
                    break
                time.sleep(0.05)
            self.assertIn("Garder Deux", texte)

    def test_familles_de_secrets_rapprochees(self):
        from vigie import duel
        self.assertEqual(duel._famille("github-pat"), duel._famille("Github"))


class Complements(unittest.TestCase):
    def test_dnsrecon_services_et_ipv6(self):
        from vigie.modules import complements
        infos = complements.lire_dnsrecon([
            {"type": "SRV", "name": "_imaps._tcp.ex.fr"}, {"type": "SRV", "name": "_submission._tcp.ex.fr"},
            {"type": "AAAA", "address": "2001:db8::1"}, {"type": "A", "address": "203.0.113.5"}])
        self.assertEqual(infos["services"], ["lecture des mails (IMAP chiffré)", "envoi des mails"])
        self.assertEqual(infos["ipv6"], ["2001:db8::1"])

    def test_unlighthouse_pages_lentes(self):
        from vigie.modules import complements
        with tempfile.TemporaryDirectory() as d:
            for chemin, ms in (("a", 5600), ("b/c", 1200)):
                os.makedirs(os.path.join(d, chemin))
                with open(os.path.join(d, chemin, "lighthouse.json"), "w") as f:
                    json.dump({"finalUrl": "https://ex.fr/" + chemin, "audits": {
                        "largest-contentful-paint": {"numericValue": ms}}}, f)
            pages, lentes = complements.lire_unlighthouse(d)
        self.assertEqual((pages, lentes), (2, [(5.6, "https://ex.fr/a")]))


class Mandat(unittest.TestCase):
    def fiche(self, **k):
        from vigie import mandat
        valeurs = dict(societe="Société <Test>", representant="Jean Patron",
                       cibles=["Ex.fr ", "203.0.113.5"], debut="2026-12-01", fin="2026-12-15")
        valeurs.update(k)
        return mandat.creer(**valeurs)

    def test_document_et_fiche(self):
        from vigie import mandat
        fiche = self.fiche()
        self.assertEqual(fiche["cibles"], ["ex.fr", "203.0.113.5"])
        page = mandat.en_html(fiche)
        self.assertIn("Société &lt;Test&gt;", page)                     # échappé
        self.assertIn("323-1", page)
        self.assertIn("partagé", page)                                 # hébergement mutualisé
        with tempfile.TemporaryDirectory() as dossier:
            _, chemin_json = mandat.ecrire(fiche, dossier)
            self.assertEqual(mandat.lire(chemin_json)["numero"], fiche["numero"])

    def test_dates_et_tests_verifies(self):
        with self.assertRaises(ValueError):
            self.fiche(debut="2026-12-15", fin="2026-12-01")
        with self.assertRaises(ValueError):
            self.fiche(tests=["tout"])

    def test_couverture(self):
        import datetime
        from vigie import mandat
        fiche = self.fiche()
        dans = datetime.date(2026, 12, 5)
        self.assertEqual(mandat.couvre(fiche, "EX.fr", "ports", dans), "")
        self.assertIn("périmètre", mandat.couvre(fiche, "autre.fr", "ports", dans))
        self.assertIn("pas autorisé", mandat.couvre(fiche, "ex.fr", "manuels", dans))
        self.assertIn("période", mandat.couvre(fiche, "ex.fr", "ports", datetime.date(2027, 1, 1)))


class OutilsManuels(Base):
    def preparer(self, dossier):
        from vigie import mandat
        fiche = mandat.creer("S", "Jean", ["ex.fr"], "2026-12-01", "2026-12-15", ["ports"])
        _, chemin = mandat.ecrire(fiche, dossier)
        signee = os.path.join(dossier, "signee.pdf")
        with open(signee, "wb") as f:
            f.write(b"%PDF signe")
        return chemin, signee

    def journal(self, dossier):
        with open(os.path.join(dossier, "j", "lancements.jsonl"), encoding="utf-8") as f:
            return [json.loads(l) for l in f]

    def test_lancement_en_regle_et_journal(self):
        import datetime
        from vigie import manuel
        appels = []
        outils.executer = lambda nom, args, **k: appels.append((nom, args)) or "<nmaprun/>"
        with tempfile.TemporaryDirectory() as d:
            fiche, signee = self.preparer(d)
            sortie = manuel.lancer("nmap", "ex.fr", fiche, signee, "ex.fr",
                                   os.path.join(d, "j"), jour=datetime.date(2026, 12, 2))
            self.assertTrue(os.path.exists(sortie))
            self.assertEqual(appels[0][1][-1], "ex.fr")
            etapes = [e["resultat"] for e in self.journal(d)]
            self.assertEqual(etapes, ["lancé", "fini"])
            self.assertEqual(len(self.journal(d)[0]["empreinte_sha256"]), 64)

    def test_refus_tous_journalises(self):
        import datetime
        from vigie import manuel
        outils.executer = lambda *a, **k: self.fail("l'outil ne doit jamais partir")
        jour = datetime.date(2026, 12, 2)
        with tempfile.TemporaryDirectory() as d:
            fiche, signee = self.preparer(d)
            j = os.path.join(d, "j")
            cas = [("sqlmap", "ex.fr", fiche, signee, "ex.fr", jour),     # pas un outil manuel
                   ("nmap", "-oN/etc/x", fiche, signee, "-oN/etc/x", jour),  # injection d'option
                   ("nmap", "autre.fr", fiche, signee, "autre.fr", jour),  # hors périmètre
                   ("nuclei", "ex.fr", fiche, signee, "ex.fr", jour),     # test non signé
                   ("nmap", "ex.fr", fiche, signee, "ex.fr", datetime.date(2027, 1, 1)),
                   ("nmap", "ex.fr", fiche, os.path.join(d, "absent.pdf"), "ex.fr", jour),
                   ("nmap", "ex.fr", fiche, signee, "", jour)]              # pas de confirmation
            for nom, cible, f, s, conf, quand in cas:
                with self.assertRaises(manuel.Refus):
                    manuel.lancer(nom, cible, f, s, conf, j, jour=quand)
            self.assertEqual([e["resultat"] for e in self.journal(d)], ["refusé"] * len(cas))


class OngletManuel(Base):
    def test_autorisation_puis_lancement_depuis_l_interface(self):
        import datetime
        from vigie import mandat
        vrai = (interface.AUTORISATIONS, interface.JOURNAL)
        outils.executer = lambda *a, **k: "<nmaprun/>"
        with tempfile.TemporaryDirectory() as d:
            interface.AUTORISATIONS, interface.JOURNAL = os.path.join(d, "a"), os.path.join(d, "j")
            self.addCleanup(lambda: setattr(interface, "AUTORISATIONS", vrai[0]))
            self.addCleanup(lambda: setattr(interface, "JOURNAL", vrai[1]))
            serveur = ThreadingHTTPServer(("127.0.0.1", 0), interface.fabrique(d, ""))
            threading.Thread(target=serveur.serve_forever, daemon=True).start()
            self.addCleanup(serveur.shutdown)
            self.addCleanup(serveur.server_close)
            base = f"http://127.0.0.1:{serveur.server_address[1]}"
            self.assertIn("Outils manuels", urllib.request.urlopen(base + "/manuel").read().decode())
            aujourd_hui = datetime.date.today()
            fin = aujourd_hui + datetime.timedelta(days=3)
            corps = (f"societe=S&representant=Jean&cibles=ex.fr&debut={aujourd_hui}"
                     f"&fin={fin}&tests=ports").encode()
            page = urllib.request.urlopen(base + "/manuel/autorisation", data=corps).read().decode()
            numero = re.search(r"/manuel/autorisation/([0-9a-f-]{15})", page).group(1)
            self.assertIn("323-1", urllib.request.urlopen(
                base + "/manuel/autorisation/" + numero).read().decode())
            with open(os.path.join(d, "a", "signee.pdf"), "wb") as f:
                f.write(b"%PDF")
            fiche = f"autorisation_{numero}.json"
            # sans confirmation : refusé, rien ne part
            with self.assertRaises(urllib.error.HTTPError) as refus:
                urllib.request.urlopen(base + "/manuel/lancer", data=(
                    f"outil=nmap&cible=ex.fr&fiche={fiche}&signee=signee.pdf").encode())
            self.assertEqual(refus.exception.code, 400)
            reponse = urllib.request.urlopen(base + "/manuel/lancer", data=(
                f"outil=nmap&cible=ex.fr&fiche={fiche}&signee=signee.pdf"
                "&confirmation=ex.fr").encode())
            for _ in range(100):
                texte = urllib.request.urlopen(reponse.geturl()).read().decode()
                if "En cours" not in texte:
                    break
                time.sleep(0.05)
            self.assertIn("Terminé", texte)
            self.assertIn("Aucun service ouvert", texte)
            requete = urllib.request.Request(base + "/manuel/lancer", data=b"x=1",
                                             headers={"Origin": "https://site-piege.fr"})
            with self.assertRaises(urllib.error.HTTPError) as piege:
                urllib.request.urlopen(requete)
            self.assertEqual(piege.exception.code, 403)
            self.assertTrue(mandat.lire(os.path.join(d, "a", fiche)))


class Ports(unittest.TestCase):
    XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
      <address addr="192.168.1.20" addrtype="ipv4"/><hostnames><hostname name="pc-bureau"/></hostnames>
      <ports><port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
      <port protocol="tcp" portid="49999"><state state="open"/><service name="unknown"/></port></ports></host>
      <host><status state="down"/><address addr="192.168.1.30" addrtype="ipv4"/></host></nmaprun>"""

    def test_lecture_et_traduction(self):
        from vigie import ports
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(self.XML)
        self.addCleanup(os.remove, f.name)
        appareils = ports.lire_nmap(f.name)
        self.assertEqual(len(appareils), 1)                         # l'appareil éteint est ignoré
        self.assertEqual([p["port"] for p in appareils[0]["ports"]], [3389, 49999])  # fermé ignoré
        lignes = ports.traduire(appareils)
        self.assertEqual(lignes[0][0], CRITIQUE)                    # le bureau à distance d'abord
        self.assertIn("pc-bureau", lignes[0][1])
        self.assertIn("non identifié", lignes[1][1])


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


class TestAuditActif(unittest.TestCase):
    """Traducteurs des outils d'audit actif (naabu, nuclei, sslscan) -> français."""

    from vigie import audit_actif  # noqa: E402

    def _fichier(self, contenu, suffixe=".txt"):
        tmp = tempfile.NamedTemporaryFile("w", suffix=suffixe, delete=False, encoding="utf-8")
        tmp.write(contenu)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_naabu_traduit_les_ports_connus(self):
        from vigie import audit_actif
        contenu = ('{"ip":"10.0.1.3","host":"mail","port":3389}\n'
                   '{"ip":"10.0.1.3","host":"mail","port":80}\n')
        lignes = audit_actif.traduire_naabu(self._fichier(contenu, ".json"))
        self.assertEqual(lignes[0][0], CRITIQUE)      # 3389 (RDP) passe en tête
        self.assertIn("3389", lignes[0][1])
        self.assertTrue(any("80" in t for _, t in lignes))

    def test_naabu_ignore_les_lignes_cassees(self):
        from vigie import audit_actif
        lignes = audit_actif.traduire_naabu(self._fichier('pas du json\n\n', ".json"))
        self.assertEqual(lignes, [])

    def test_nuclei_classe_par_gravite(self):
        from vigie import audit_actif
        contenu = ('{"info":{"name":"Faille grave","severity":"critical"},"matched-at":"http://10.0.1.3"}\n'
                   '{"info":{"name":"Point mineur","severity":"info"},"host":"10.0.1.3"}\n')
        lignes = audit_actif.traduire_nuclei(self._fichier(contenu, ".jsonl"))
        self.assertEqual(lignes[0][0], CRITIQUE)
        self.assertIn("Faille grave", lignes[0][1])
        self.assertEqual(lignes[-1][0], INFO)

    def test_sslscan_signale_vieux_protocole(self):
        from vigie import audit_actif
        xml = ('<document><ssltest>'
               '<protocol type="ssl" version="3" enabled="1"/>'
               '<protocol type="tls" version="1.2" enabled="1"/>'
               '<cipher status="accepted" cipher="RC4-SHA"/>'
               '</ssltest></document>')
        lignes = audit_actif.traduire_sslscan(self._fichier(xml, ".xml"))
        self.assertEqual(lignes[0][0], CRITIQUE)          # SSLv3
        self.assertTrue(any("RC4" in t for _, t in lignes))

    def test_sslscan_rien_a_signaler(self):
        from vigie import audit_actif
        xml = '<document><ssltest><protocol type="tls" version="1.3" enabled="1"/></ssltest></document>'
        lignes = audit_actif.traduire_sslscan(self._fichier(xml, ".xml"))
        self.assertEqual(lignes[0][0], OK)

    def test_nikto_garde_les_constats(self):
        from vigie import audit_actif
        contenu = ("- Nikto v2.5\n"
                   "+ Target IP: 1.2.3.4\n"
                   "+ Server: Apache/2.2.3 (outdated)\n"
                   "+ The X-Frame-Options header is not present.\n"
                   "+ Retrieved x-powered-by header: PHP/5.3\n")
        lignes = audit_actif.traduire_nikto(self._fichier(contenu, ".txt"))
        textes = [t for _, t in lignes]
        self.assertTrue(any("X-Frame-Options" in t for t in textes))
        self.assertFalse(any("Target IP" in t for t in textes))   # l'en-tête est ignoré
        self.assertEqual(lignes[0][0], CRITIQUE)                   # serveur obsolète en tête

    def test_nikto_rien_a_signaler(self):
        from vigie import audit_actif
        lignes = audit_actif.traduire_nikto(self._fichier("- Nikto v2.5\n", ".txt"))
        self.assertEqual(lignes[0][0], OK)

    def test_katana_compte_les_pages_et_parametres(self):
        from vigie import audit_actif
        contenu = ('{"request":{"endpoint":"https://x.fr/","method":"GET"}}\n'
                   '{"request":{"endpoint":"https://x.fr/login?u=1","method":"GET"}}\n'
                   '{"endpoint":"https://x.fr/contact","request":{"method":"POST"}}\n')
        lignes = audit_actif.traduire_katana(self._fichier(contenu, ".jsonl"))
        self.assertIn("3 page", lignes[0][1])
        self.assertTrue(any("2 avec" in t for _, t in lignes))

    def test_tlsx_signale_certificat_expire(self):
        from vigie import audit_actif
        contenu = '{"host":"x.fr","expired":true,"not_after":"2024-01-01"}\n'
        lignes = audit_actif.traduire_tlsx(self._fichier(contenu, ".jsonl"))
        self.assertEqual(lignes[0][0], CRITIQUE)
        self.assertIn("expiré", lignes[0][1])

    def test_tlsx_rien_a_signaler(self):
        from vigie import audit_actif
        lignes = audit_actif.traduire_tlsx(self._fichier('{"host":"x.fr"}\n', ".jsonl"))
        self.assertEqual(lignes[0][0], OK)

    def test_outils_manuels_connaissent_naabu_et_sslscan(self):
        from vigie import manuel, outils, audit_actif
        for nom in ("nmap", "nuclei", "naabu", "sslscan", "nikto", "katana", "tlsx"):
            self.assertIn(nom, manuel.OUTILS)
            self.assertIn("test", manuel.OUTILS[nom])
            self.assertIn(manuel.OUTILS[nom]["outil"], outils.CATALOGUE)
        # chaque outil actif a sa traduction française (pas de sortie brute à l'écran)
        for nom in ("naabu", "nuclei", "sslscan", "nikto", "katana", "tlsx"):
            self.assertIn(nom, audit_actif.TRADUCTEURS)


class TestRegistre(unittest.TestCase):
    """Le registre des 222 outils du catalogue (registre.py)."""

    def test_charge_les_220_outils_trouves(self):
        from vigie import registre
        tout = registre.charger()
        self.assertEqual(len(tout), 220)          # 222 - 2 introuvables
        self.assertTrue(all("famille" in o for o in tout))

    def test_familles_bien_reparties(self):
        from vigie import registre
        g = registre.par_famille()
        self.assertEqual(len(g["diag"]), 42)
        self.assertEqual(len(g["gate"]), 66)

    def test_outils_offensifs_exigent_autorisation(self):
        from vigie import registre
        for o in registre.charger():
            if o["attaque"]:
                self.assertTrue(o["autorisation_requise"])
                self.assertTrue(o["actif"])

    def test_payants_marques_et_non_installables(self):
        from vigie import registre
        payants = [o for o in registre.charger() if o["payant"]]
        self.assertIn("uncover", [o["nom"].lower() for o in payants])
        self.assertTrue(all(not o["installable"] for o in payants))

    def test_diag_est_passif_et_libre(self):
        from vigie import registre
        for o in registre.par_famille()["diag"]:
            self.assertFalse(o["autorisation_requise"])


class TestLancerSeul(unittest.TestCase):
    """Mode « lancer chaque outil un par un » (lancer_seul.py)."""

    def test_ligne_verifiee_pour_outil_declare(self):
        from vigie import lancer_seul
        commande, arguments, verifiee = lancer_seul.ligne_lancement("subfinder", "ex.fr")
        self.assertEqual(commande, "subfinder")
        self.assertIn("ex.fr", arguments)
        self.assertTrue(verifiee)

    def test_ligne_devinee_depuis_usage(self):
        from vigie import lancer_seul
        commande, arguments, verifiee = lancer_seul.ligne_lancement("Sherlock", "vigie")
        self.assertEqual(commande, "sherlock")
        self.assertEqual(arguments, ["vigie"])
        self.assertFalse(verifiee)                 # devinée, à confirmer

    def test_outil_interactif_sans_ligne(self):
        from vigie import lancer_seul
        self.assertIsNone(lancer_seul.ligne_lancement("Recon-ng", "ex.fr"))

    def test_deviné_cassé_pas_proposé(self):
        # Les usages à plusieurs trous (URL + dictionnaire) ou où la cible atterrit sur
        # un fichier / le nom du programme ne sont plus devinés (26/11/2026) : avant,
        # « gobuster -u {url} -w {wordlist} » mettait la cible dans le dictionnaire,
        # « hydra -P {cible} » dans la liste de mots de passe, « bash airgeddon.sh » sur
        # le script. On préfère ne rien proposer qu'une commande cassée.
        from vigie import lancer_seul
        for nom in ("gobuster", "feroxbuster", "ffuf", "THC-Hydra", "Medusa",
                    "airgeddon", "enum4linux-ng"):
            self.assertFalse(lancer_seul.lancable_ici(nom),
                             f"{nom} ne devrait plus être proposé au lancement")

    def test_xsstrike_a_sa_vraie_recette(self):
        # XSStrike : l'usage « python xsstrike.py -u … » n'est plus deviné, mais
        # l'installeur écrit un lanceur « xsstrike » : sa fiche donne la vraie ligne.
        from vigie import lancer_seul
        commande, arguments, verifiee = lancer_seul.ligne_lancement("XSStrike",
                                                                     "https://ex.fr/?q=1")
        self.assertEqual((commande, arguments, verifiee),
                         ("xsstrike", ["-u", "https://ex.fr/?q=1"], True))
        self.assertTrue(lancer_seul.lancable_ici("XSStrike"))

    def test_recette_cewl_corrigee(self):
        # CeWL tombait en erreur : la cible remplaçait « wordlist.txt ». Recette propre.
        from vigie import lancer_seul
        commande, arguments, verifiee = lancer_seul.ligne_lancement("CeWL", "https://ex.fr/")
        self.assertEqual(commande, "cewl")
        self.assertEqual(arguments[-1], "https://ex.fr/")     # la cible, au bon endroit
        self.assertTrue(verifiee)

    def test_outils_web_ont_une_recette(self):
        # Le bloc domaine/URL : vraies recettes, plus de « ne sait pas lancer ».
        from vigie import lancer_seul
        for nom in ("Nikto", "Wapiti", "Katana", "Dalfox", "dirsearch", "sqlmap", "tlsx",
                    "WPProbe"):
            self.assertTrue(lancer_seul.lancable_ici(nom), nom)

    def test_outil_sans_cible_pas_lancable(self):
        # Aircrack-ng / arp-scan : pas de cible (Wi-Fi, réseau local) -> jamais « lançable ».
        from vigie import lancer_seul
        for nom in ("Aircrack-ng", "arp-scan", "Masscan", "Betterleaks"):
            self.assertFalse(lancer_seul.lancable_ici(nom), nom)

    def test_refuse_outil_actif_sans_autorisation(self):
        from vigie import lancer_seul
        with self.assertRaises(lancer_seul.Refus):
            lancer_seul.verifier_lancable("nuclei", autorisation_ok=False)

    def test_refuse_outil_payant(self):
        from vigie import lancer_seul
        with self.assertRaises(lancer_seul.Refus):
            lancer_seul.verifier_lancable("uncover")

    def test_outil_passif_est_lancable(self):
        from vigie import lancer_seul
        # Sherlock (diag/passif) : aucune exception.
        lancer_seul.verifier_lancable("Sherlock", autorisation_ok=False)

    def test_lancer_refuse_actif(self):
        from vigie import lancer_seul
        with self.assertRaises(lancer_seul.Refus):
            lancer_seul.lancer("nmap", "ex.fr")


class TestInterfaceOutils(unittest.TestCase):
    """Onglet « Lancer un outil » (interface_outils.py)."""

    def test_page_liste_les_familles(self):
        from vigie import interface_outils
        p = interface_outils.page()
        self.assertIn("Lancer un outil", p)
        self.assertIn("optgroup", p)                 # outils passifs proposés
        self.assertIn("Offensif", p)                 # catalogue complet affiché

    def test_page_resultat_inconnu(self):
        from vigie import interface_outils
        self.assertIsNone(interface_outils.page_resultat("inexistant"))

    def test_lancer_refuse_actif(self):
        from vigie import interface_outils, lancer_seul
        with self.assertRaises(lancer_seul.Refus):
            interface_outils.lancer("nom=nmap&cible=ex.fr")

    def test_lancer_refuse_cible_vide(self):
        from vigie import interface_outils, lancer_seul
        with self.assertRaises(lancer_seul.Refus):
            interface_outils.lancer("nom=Sherlock&cible=")

    def test_page_montre_les_outils_installes(self):
        # Les outils présents sur la machine sont marqués « installé » et comptés ;
        # dans la liste à lancer, ils viennent en tête avec un « ✓ ».
        from vigie import interface_outils, presence
        with mock.patch.object(presence, "etat", return_value={"Sherlock": True}):
            p = interface_outils.page()
        self.assertIn("m-installe'>installé", p)
        self.assertIn("<b>1</b> outil sur\n216 est installé", p)
        self.assertIn("— 1 installé</h2>", p)
        self.assertIn("✓ Sherlock", p)
        premier = re.search(r"<optgroup label='Diagnostic[^']*'><option value='([^']+)'", p)
        self.assertEqual(premier.group(1), "Sherlock")

    def test_badges_catalogue_honnetes(self):
        # Un outil sans recette ne doit JAMAIS être marqué « lançable » : il est « à la
        # main » (Aircrack-ng) ou « à ouvrir » s'il a sa propre interface (OWASP ZAP).
        from vigie import interface_outils
        p = interface_outils.page()
        self.assertRegex(p, r"<li>Aircrack-ng<span class='marque m-main'>à la main</span>")
        self.assertRegex(p, r"<li>OWASP ZAP<span class='marque m-ouvrir'>à ouvrir</span>")
        self.assertRegex(p, r"<li>Sherlock<span class='marque m-pret'>lançable</span>")

    def test_outil_sans_recette_absent_du_menu(self):
        # Les outils non lançables ne sont plus proposés dans le menu déroulant.
        from vigie import interface_outils
        p = interface_outils.page()
        options = re.findall(r"<option value='([^']+)'", p)
        for nom in ("Aircrack-ng", "arp-scan", "AdGuard Home", "gobuster", "Betterleaks"):
            self.assertNotIn(nom, options, f"{nom} ne doit plus être proposé au lancement")
        self.assertIn("Sherlock", options)          # un vrai lançable reste proposé


class TestPresence(unittest.TestCase):
    """Est-ce qu'un outil est installé sur la machine ? (presence.py)"""

    def test_commande_lue_dans_l_usage(self):
        from vigie import presence
        lire = presence.binaire_usage
        self.assertEqual(lire("clamscan [options] {fichier/dossier}  (antivirus)"), "clamscan")
        self.assertEqual(lire("fail2ban-client ; surveille les logs"), "fail2ban-client")
        self.assertEqual(lire("sudo bettercap -iface eth0 ; modules"), "bettercap")
        self.assertEqual(lire("python3 -m garak --model_type ..."), "garak")
        self.assertEqual(lire("theHarvester -d {cible} -l 500"), "theHarvester")
        self.assertEqual(lire("hydra -l user -P passlist.txt ssh://cible"), "hydra")

    def test_une_phrase_n_est_pas_une_commande(self):
        # Sinon Vigie chercherait un programme « suite » ou « serveur » sur la machine.
        from vigie import presence
        for phrase in ("suite complète d'audit de sécurité WiFi",
                       "serveur DNS filtrant réseau (bloque pubs)",
                       "gestionnaire de mots de passe LOCAL",
                       "framework red team agentique IA (tests)",
                       "SURTOUT via interface web (sf.py -l host:port)",
                       "python main.py cli -m gpt-4.1",       # un script, pas l'outil
                       "./reconftw.sh -d {domaine} -r",       # lancé depuis son dossier
                       "docker run -it projectdiscovery/x"):
            self.assertIsNone(presence.binaire_usage(phrase), phrase)

    def test_le_nom_de_l_outil_n_est_pas_toujours_sa_commande(self):
        from vigie import presence
        self.assertIn("clamscan", presence.binaires_possibles("ClamAV"))
        self.assertIn("fls", presence.binaires_possibles("The Sleuth Kit"))
        self.assertIn("hydra", presence.binaires_possibles("THC-Hydra"))
        self.assertIn("nmap", presence.binaires_possibles("Nmap"))
        # Dépôt au nom trop vague (« opnsense/core ») : on ne cherche pas « core ».
        self.assertNotIn("core", presence.binaires_possibles("OPNsense"))

    def _machine(self, *commandes):
        """Une fausse machine : seuls ces exécutables existent."""
        dossier = tempfile.mkdtemp()
        for commande in commandes:
            chemin = os.path.join(dossier, commande)
            with open(chemin, "w") as f:
                f.write("#!/bin/sh\necho ok\n")
            os.chmod(chemin, 0o755)
        return [mock.patch.dict(os.environ, {"PATH": dossier}),
                mock.patch.object(outils, "DOSSIERS_OUTILS", [])]

    def test_outil_installe_via_apt_est_vu(self):
        from vigie import presence
        rustines = self._machine("clamscan", "tcpdump")
        for r in rustines:
            r.start()
        try:
            self.assertTrue(presence.installe("ClamAV"))
            self.assertTrue(presence.installe("tcpdump"))
            self.assertFalse(presence.installe("YARA"))
        finally:
            for r in rustines:
                r.stop()

    def test_aucun_faux_positif_sur_une_machine_vide(self):
        from vigie import presence
        rustines = self._machine()
        for r in rustines:
            r.start()
        try:
            etats = presence.etat(verifies={})
        finally:
            for r in rustines:
                r.stop()
        self.assertEqual([n for n, v in etats.items() if v], [])
        self.assertGreater(len(etats), 200)

    def test_commande_verifiee_par_l_installation(self):
        # Le rapport d'installation dit quelle commande a vraiment démarré : on la reprend.
        from vigie import presence
        with tempfile.TemporaryDirectory() as d:
            chemin = os.path.join(d, "vigie-installation.json")
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump({"details": [
                    {"nom": "SpiderFoot", "installe": True, "repond": True, "binaire": "sf"},
                    {"nom": "Datashare", "installe": True, "repond": False, "binaire": ""},
                ]}, f)
            verifies = presence.rapport_installation(chemin)
        self.assertEqual(verifies, {"spiderfoot": "sf"})
        self.assertIn("sf", presence.binaires_possibles("SpiderFoot", verifies))
        self.assertEqual(presence.rapport_installation("/nulle/part.json"), {})

    def test_registre_en_ligne_de_commande_marque_les_installes(self):
        import io
        from contextlib import redirect_stdout
        from vigie import registre
        tampon = io.StringIO()
        with redirect_stdout(tampon):
            registre._principal(["secu"], statut={"ClamAV": True})
        texte = tampon.getvalue()
        self.assertIn("- ClamAV  [installé]", texte)
        self.assertIn("1 est installé sur cette machine.", texte)

    def test_installeur_essaie_la_vraie_commande(self):
        # apt pose le paquet « clamav », mais la commande est « clamscan » : l'outil
        # ne doit plus passer pour « installé mais ne démarre pas ».
        outil = {"nom": "ClamAV", "lien": "https://github.com/Cisco-Talos/clamav"}
        with mock.patch.object(installeur, "_lancer", return_value=(True, "", "")), \
                mock.patch.object(installeur, "repond", side_effect=lambda b: b == "clamscan"):
            compte = installeur.installer_un(outil)
        self.assertTrue(compte["repond"])
        self.assertEqual(compte["binaire"], "clamscan")


class TestAstuceInstallation(unittest.TestCase):
    """« brew install » n'existe pas sous Linux : on montre la commande de la doc."""

    def test_linux_montre_apt(self):
        self.assertEqual(outils.astuce_installation("nmap", "linux"), "sudo apt install nmap")
        self.assertEqual(outils.astuce_installation("hydra", "linux"), "sudo apt install hydra")

    def test_mac_inchange(self):
        self.assertEqual(outils.astuce_installation("nmap", "darwin"), "brew install nmap")

    def test_pipx_inchange_partout(self):
        self.assertEqual(outils.astuce_installation("sherlock", "linux"),
                         "pipx install sherlock-project")

    def test_jamais_brew_sous_linux(self):
        for nom in outils.CATALOGUE:
            self.assertFalse(outils.astuce_installation(nom, "linux").startswith("brew"), nom)


class TestInstallTousNonPayants(unittest.TestCase):
    """Installation en masse : méthode apt + exclusion des payants + plus d'outils lançables."""

    def test_methode_apt_reconnue(self):
        from vigie import installeur
        outil = {"nom": "ExifTool", "lien": "https://github.com/exiftool/exiftool"}
        essais = installeur.methodes(outil, install="sudo apt install libimage-exiftool-perl")
        apt = [cmd for lib, cmd in essais if lib.startswith("apt (documenté)")]
        self.assertTrue(apt, "aucune commande apt reconnue")
        for cmd in apt:
            self.assertEqual(cmd[0], "sudo")
            self.assertIn("apt-get", cmd)
            self.assertIn("install", cmd)
            # Aucune question à l'écran (Wireshark en posait une et bloquait tout).
            self.assertIn("DEBIAN_FRONTEND=noninteractive", cmd)
            # apt doit ATTENDRE le verrou au lieu d'échouer tout de suite.
            self.assertTrue(any(c.startswith("DPkg::Lock::Timeout=") for c in cmd))
            self.assertEqual(cmd[-1], "libimage-exiftool-perl")

    def test_payants_exclus_du_registre(self):
        from vigie import registre
        self.assertIn("uncover", registre.noms_payants())
        self.assertIn("robin", registre.noms_payants())

    def test_usage_avec_exemple_de_cible(self):
        from vigie import lancer_seul
        # PhoneInfoga : usage « phoneinfoga scan -n '+33679368229' » -> cible substituée.
        commande, arguments, _ = lancer_seul.ligne_lancement("PhoneInfoga", "+33600000000")
        self.assertEqual(commande, "phoneinfoga")
        self.assertIn("+33600000000", arguments)

    def test_plus_de_80_outils_lancables(self):
        from vigie import registre, lancer_seul
        lancables = sum(1 for o in registre.non_payants()
                        if lancer_seul.ligne_lancement(o["nom"], "cible.fr"))
        self.assertGreaterEqual(lancables, 70)

    def test_dest_regle_les_variables_et_cree_le_dossier(self):
        import os
        import tempfile
        from vigie import installeur
        variables = ("PIPX_HOME", "PIPX_BIN_DIR", "GOPATH", "GOBIN", "GOMODCACHE",
                     "GOCACHE", "PIP_CACHE_DIR", "TMPDIR", "PATH")
        garde = {c: os.environ.get(c) for c in variables}
        try:
            with tempfile.TemporaryDirectory() as dossier:
                cible = os.path.join(dossier, "vigie-outils")
                bin_dir = installeur.preparer_dest(cible)
                self.assertTrue(os.path.isdir(bin_dir))
                self.assertEqual(os.environ["PIPX_BIN_DIR"], bin_dir)
                self.assertEqual(os.environ["GOBIN"], bin_dir)
                self.assertTrue(os.environ["PATH"].startswith(bin_dir))
                # Les caches (go-build, pip) et le temp doivent aussi être SOUS le
                # dossier cible, sinon ils remplissent le disque système.
                for cle in ("GOCACHE", "PIP_CACHE_DIR", "TMPDIR", "GOMODCACHE"):
                    self.assertTrue(os.environ[cle].startswith(cible),
                                    f"{cle} = {os.environ[cle]} n'est pas sous {cible}")
        finally:
            for cle, valeur in garde.items():
                if valeur is None:
                    os.environ.pop(cle, None)
                else:
                    os.environ[cle] = valeur

    def test_vigie_cherche_dans_le_dossier_dest(self):
        from vigie import outils
        self.assertIn("/opt/vigie-outils/bin", outils.DOSSIERS_OUTILS)

    def test_specs_go_ont_le_prefixe_github(self):
        # Naabu et tlsx : la ligne « go install » doit viser github.com/… (sinon
        # go tente un module introuvable et l'install échoue).
        from vigie import installeur
        docs = installeur.charger(installeur.DOCS) if hasattr(installeur, "DOCS") else None
        import json
        import os
        chemin = os.path.join(os.path.dirname(installeur.__file__), "docs_outils.json")
        fiches = {o["nom"]: o for o in json.load(open(chemin, encoding="utf-8"))}
        for nom in ("Naabu", "tlsx"):
            essais = installeur.methodes(fiches[nom])
            go = [cmd for lib, cmd in essais if lib.startswith("go (documenté)")]
            self.assertTrue(go, f"{nom} : aucune commande go documentée reconnue")
            self.assertTrue(all(c[-1].startswith("github.com/") for c in go),
                            f"{nom} : module go sans github.com/")

    def test_reprendre_ne_reessaie_que_les_echecs(self):
        # --reprendre : un outil marqué installé dans le rapport précédent est gardé,
        # pas réessayé ; seuls les échecs repartent.
        import json
        import os
        import subprocess
        import sys
        import tempfile
        rapport = {"resume": {}, "details": [
            {"nom": "Sherlock", "installe": True, "repond": True},
            {"nom": "Naabu", "installe": False, "repond": False},
        ]}
        with tempfile.TemporaryDirectory() as d:
            chemin = os.path.join(d, "prec.json")
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump(rapport, f)
            sortie = os.path.join(d, "out.json")
            res = subprocess.run(
                [sys.executable, "-m", "vigie", "installer", "--tous", "--a-blanc",
                 "--reprendre", chemin, "--rapport", sortie],
                capture_output=True, text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.assertIn("déjà prêts gardés", res.stdout)
            # Le rapport final garde Sherlock (déjà prêt) sans l'avoir réessayé.
            with open(sortie, encoding="utf-8") as f:
                final = json.load(f)
            noms_ok = {d["nom"] for d in final["details"] if d.get("installe")}
            self.assertIn("Sherlock", noms_ok)

    def test_reprendre_reverifie_ceux_qui_ne_demarraient_pas(self):
        # Un outil « installé mais ne démarre pas » n'est PAS gardé tel quel : souvent on
        # cherchait la mauvaise commande (clamav au lieu de clamscan). Il est revérifié.
        import json
        import os
        import subprocess
        import sys
        import tempfile
        rapport = {"resume": {}, "details": [
            {"nom": "Sherlock", "installe": True, "repond": True},
            {"nom": "ClamAV", "installe": True, "repond": False},
        ]}
        with tempfile.TemporaryDirectory() as d:
            chemin = os.path.join(d, "prec.json")
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump(rapport, f)
            res = subprocess.run(
                [sys.executable, "-m", "vigie", "installer", "--tous", "--a-blanc",
                 "--reprendre", chemin, "--rapport", os.path.join(d, "out.json")],
                capture_output=True, text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.assertIn("Reprise : 1 outils déjà prêts gardés", res.stdout)
            self.assertIn("ClamAV", res.stdout)          # il repart dans la liste


class TestInstallerParFamille(unittest.TestCase):
    """Installer par famille (pour tenir dans un petit disque)."""

    def test_famille_diag_a_blanc(self):
        import io
        from contextlib import redirect_stdout
        tampon = io.StringIO()
        with redirect_stdout(tampon):
            cli.main(["installer", "--famille", "diag", "--a-blanc", "--limite", "2"])
        texte = tampon.getvalue()
        self.assertIn("à blanc", texte)
        self.assertIn("payants écartés", texte)


class TestExplicationsEnFrancais(unittest.TestCase):
    """Chaque lancement d'outil dit en français pourquoi ça marche ou pas."""

    def test_chaque_outil_lancable_a_sa_fiche(self):
        from vigie import fiches_outils, registre
        for o in registre.charger():
            if o["famille"] in ("diag", "secu") and not o["payant"]:
                f = fiches_outils.FICHES.get(o["nom"].lower())
                self.assertIsNotNone(f, f"{o['nom']} : pas de fiche en clair")
                self.assertIn(f["mode"], fiches_outils.MODES, o["nom"])
                self.assertIn(f["cible"], fiches_outils.CIBLES, o["nom"])
                self.assertTrue(f["role"], o["nom"])

    def test_reconnaitre_la_cible(self):
        from vigie.fiches_outils import type_de
        self.assertEqual(type_de("https://ex.fr/a"), "url")
        self.assertEqual(type_de("contact@ex.fr"), "email")
        self.assertEqual(type_de("06 12 34 56 78"), "telephone")
        self.assertEqual(type_de("192.168.1.1"), "ip")
        self.assertEqual(type_de("/home/moi/photo.jpg"), "chemin")
        self.assertEqual(type_de("pavillon-noir.tech"), "domaine")
        self.assertEqual(type_de("eldjango30"), "pseudo")
        self.assertEqual(type_de("deux mots"), "texte")

    def test_service_explique_au_lieu_de_lancer(self):
        # Cas réel du 24/11/2026 : AdGuard Home lancé sur un pseudo.
        from vigie import lancer_seul
        with self.assertRaises(lancer_seul.Refus) as refus:
            lancer_seul.preparer("AdGuard Home", "eldjango30")
        self.assertIn("service", str(refus.exception))
        self.assertIn("eldjango30", str(refus.exception))

    def test_archivebox_explique_sa_preparation(self):
        # Cas réel du 24/11/2026 : ArchiveBox sur un pseudo -> erreurs anglaises brutes.
        from vigie import lancer_seul
        with self.assertRaises(lancer_seul.Refus) as refus:
            lancer_seul.preparer("ArchiveBox", "eldjango30")
        self.assertIn("archivebox init", str(refus.exception))

    def test_mauvaise_cible_expliquee(self):
        from vigie import lancer_seul
        for nom, cible, attendu in (("Sherlock", "https://ex.fr", "pseudo"),
                                    ("Holehe", "eldjango30", "adresse e-mail"),
                                    ("ExifTool", "pavillon-noir.tech", "fichier")):
            with self.assertRaises(lancer_seul.Refus) as refus:
                lancer_seul.preparer(nom, cible)
            self.assertIn(attendu, str(refus.exception), nom)

    def test_cible_arrangee_quand_sans_risque(self):
        from vigie import lancer_seul
        prepa = lancer_seul.preparer("Subfinder", "https://pavillon-noir.tech/contact")
        self.assertEqual(prepa["cible"], "pavillon-noir.tech")
        self.assertTrue(prepa["remarques"])
        self.assertEqual(lancer_seul.preparer("Lighthouse", "ex.fr")["cible"], "https://ex.fr")
        self.assertEqual(lancer_seul.preparer("PhoneInfoga", "06 12 34 56 78")["cible"],
                         "+33612345678")
        lynis = lancer_seul.preparer("Lynis", "")
        self.assertEqual(lynis["ligne"][0], "lynis")

    def test_windows_capture_ressource_compte(self):
        from vigie import lancer_seul
        for nom, mot in (("HardeningKitty", "Windows"), ("tcpdump", "carte réseau"),
                         ("Sigma", "pas un programme"), ("GHunt", "ghunt login"),
                         ("Ghidra", "logiciel")):
            with self.assertRaises(lancer_seul.Refus) as refus:
                lancer_seul.preparer(nom, "x")
            self.assertIn(mot, str(refus.exception), nom)

    def test_erreurs_traduites(self):
        from vigie import erreurs
        self.assertIn("DNS", erreurs.expliquer("curl: (6) Could not resolve host: x")[0])
        self.assertIn("Python", erreurs.expliquer("ModuleNotFoundError: No module named 'x'")[0])
        self.assertIn("ligne", erreurs.expliquer("error: unrecognized arguments: -z")[0])
        self.assertEqual(erreurs.expliquer("tout va bien"), [])

    def test_echecs_d_installation_traduits(self):
        from vigie import erreurs
        self.assertIn("relancer", erreurs.expliquer_installation(
            "apt (documenté) : E: Could not get lock /var/lib/dpkg/lock-frontend")[0])
        self.assertIn("Mac", erreurs.expliquer_installation("brew (documenté) : brew absent")[0])
        self.assertIn("pas un", erreurs.expliquer_installation(
            "pipx (dépôt) : ERROR: neither 'setup.py' nor 'pyproject.toml' found")[0])

    def test_outil_absent_explique_l_installation_ratee(self):
        from vigie import lancer_seul, presence
        vrai = presence.echecs_installation
        presence.echecs_installation = lambda chemin=None: {
            "sherlock": "pipx (documenté) : pipx absent"}
        try:
            phrases = lancer_seul.expliquer("Sherlock", {"absent": True,
                                                         "commande_absente": "sherlock"})
        finally:
            presence.echecs_installation = vrai
        texte = " ".join(phrases)
        self.assertIn("n'est pas installé", texte)
        self.assertIn("pipx", texte)
        self.assertIn("installeur", texte)

    def test_echec_au_lancement_explique(self):
        from vigie import lancer_seul
        phrases = lancer_seul.expliquer("Subfinder", {
            "lance": True, "code": 1, "verifiee": True, "sortie": "",
            "erreurs": "Temporary failure in name resolution"})
        self.assertIn("DNS", " ".join(phrases))
        inconnu = lancer_seul.expliquer("X", {"lance": True, "code": 2, "verifiee": False,
                                              "sortie": "boum"})
        self.assertIn("devinée", " ".join(inconnu))

    def test_rapport_d_installation_lu(self):
        import json
        import tempfile
        from vigie import presence
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"details": [{"nom": "Maigret", "repond": False, "raison": "npm ERR!"},
                                   {"nom": "Sherlock", "repond": True}]}, f)
        self.assertEqual(presence.echecs_installation(f.name), {"maigret": "npm ERR!"})

    def test_pas_de_repli_pipx_go_hors_langage(self):
        # Avant : pipx ET go essayés sur tous les dépôts, même Docker ou Node.
        from vigie import installeur
        outil = {"nom": "Uptime Kuma", "lien": "https://github.com/louislam/uptime-kuma"}
        self.assertEqual(installeur.methodes(
            outil, install="docker louislam/uptime-kuma ; npm ; git clone (Node.js 18+)"), [])
        self.assertIn("à la main", installeur.installer_un(outil)["raison"])
        go = installeur.methodes({"nom": "G", "lien": "https://github.com/a/g"},
                                 install="go build ./...")
        self.assertEqual([l for l, _ in go], ["go (dépôt)"])

    def test_page_resultat_explique_et_garde_le_brut(self):
        from vigie import interface_outils
        interface_outils.LANCEMENTS["essai-explication"] = {
            "etat": "erreur", "outil": "Subfinder", "cible": "ex.fr", "reussi": False,
            "explication": ["Subfinder s'est arrêté en erreur.", "Problème de DNS."],
            "resultat": "", "brut": "Temporary failure in name resolution",
            "commande": "subfinder -d ex.fr"}
        try:
            p = interface_outils.page_resultat("essai-explication")
        finally:
            del interface_outils.LANCEMENTS["essai-explication"]
        self.assertIn("Ce qui s'est passé", p)
        self.assertIn("Problème de DNS.", p)
        self.assertIn("<details", p)
        self.assertIn("Temporary failure", p)

    def test_page_montre_a_quoi_sert_l_outil(self):
        from vigie import interface_outils
        p = interface_outils.page()
        self.assertIn("data-aide=", p)
        self.assertIn("Cible : un pseudo", p)
        with self.assertRaises(interface_outils.lancer_seul.Refus):
            interface_outils.lancer("nom=AdGuard+Home&cible=eldjango30")


# ---------------------------------------------------------------------------
# Diagnostic complet : les 42 outils de la famille « diagnostic gratuit » (24/11/2026).

class Fini:
    """Ce que renvoie subprocess.run : code, sortie, erreurs."""
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class DiagComplet(Base):
    def test_les_42_ont_chacun_une_ligne(self):
        from vigie import diag_gratuit
        from vigie.modules import COMPLET
        self.assertEqual(sorted(diag_gratuit.OUTILS), diag_gratuit.noms_famille())
        self.assertEqual(len(diag_gratuit.OUTILS), 42)
        for nom, fiche in diag_gratuit.OUTILS.items():
            if "raison" in fiche:
                self.assertTrue(len(fiche["raison"]) > 40, nom)
                continue
            self.assertIn(fiche["module"], COMPLET, nom)
            self.assertIn(fiche["commande"], outils.CATALOGUE, nom)
            self.assertFalse(MODULES[fiche["module"]]["actif"], nom)
        # Garde-fou : le dark web (fuites) n'est jamais lancé à froid.
        self.assertTrue(diag_gratuit.OUTILS["Robin"]["ecarte"])
        self.assertIn("dark web", diag_gratuit.OUTILS["Robin"]["raison"])

    def test_complet_sans_rien_d_actif(self):
        from vigie.modules import COMPLET
        self.assertTrue(set(PAR_DEFAUT) <= set(COMPLET))
        self.assertFalse([n for n in COMPLET if MODULES[n]["actif"]])
        self.assertNotIn("conformite", COMPLET)
        for nom in COMPLET:
            for avant in MODULES[nom].get("apres", ()):
                self.assertLess(COMPLET.index(avant), COMPLET.index(nom), nom)

    def test_bilan_dit_pourquoi(self):
        from vigie import diag_gratuit
        deroule = [
            {"module": "sousdomaines", "nom": "Sous", "etat": "fini",
             "detail": "1 point(s) relevé(s)", "duree": 12.0},
            {"module": "alias_dns", "nom": "dnsx", "etat": "non_realise",
             "detail": "réseau coupé", "duree": 1.0},
        ]
        lignes = {l["outil"]: l for l in diag_gratuit.bilan(
            deroule, installe=lambda commande: commande != "gau")}
        self.assertEqual(len(lignes), 42)
        self.assertEqual(lignes["Subfinder"]["etat"], "lance")
        self.assertEqual(lignes["Subfinder"]["duree"], 12.0)
        self.assertEqual(lignes["dnsx"]["etat"], "non_realise")
        self.assertIn("réseau coupé", lignes["dnsx"]["texte"])
        self.assertEqual(lignes["gau"]["etat"], "hors_liste")
        self.assertEqual(lignes["Pi-hole"]["etat"], "jamais")
        lignes = {l["outil"]: l for l in diag_gratuit.bilan(
            [{"module": "archives", "nom": "A", "etat": "fini", "detail": "", "duree": 1}],
            installe=lambda commande: False)}
        self.assertEqual(lignes["gau"]["etat"], "absent")
        self.assertIn("à installer", lignes["gau"]["texte"])

    def test_lancement_en_parallele_avec_ordre_et_delai(self):
        vus = {}

        def lent(nom, pause, niveau=INFO):
            def fonction(cible):
                time.sleep(pause)
                return [Constat("Exposition", niveau, f"Point {nom}", "x", cle="meme")], \
                    {"liste": [nom]}
            return fonction

        def apres_a(cible):
            vus["a"] = cible.indices.get("a")
            return [], {}

        def plante(cible):
            raise RuntimeError("bug")

        modules = {
            "a": {"fonction": lent("a", 0.4), "actif": False, "nom": "A", "bloc": "Exposition"},
            "b": {"fonction": lent("b", 0.4, IMPORTANT), "actif": False, "nom": "B",
                  "bloc": "Exposition"},
            "c": {"fonction": apres_a, "actif": False, "nom": "C", "apres": ["a"]},
            "d": {"fonction": plante, "actif": False, "nom": "D"},
            "e": {"fonction": lent("e", 5), "actif": False, "nom": "E", "delai": -58},
        }
        etapes = []
        with mock.patch.dict(cli.MODULES, modules):
            debut = time.monotonic()
            r = cli.lancer(Cible("ex.fr"), ["a", "b", "c", "d", "e"],
                           suivi=lambda nom, etat, detail: etapes.append((nom, etat)))
            duree = time.monotonic() - debut
        self.assertLess(duree, 4.5)                       # a et b ensemble, e abandonné
        self.assertEqual(vus["a"], {"liste": ["a"]})      # c a attendu a
        self.assertLess(etapes.index(("a", "fini")), etapes.index(("c", "en_cours")))
        raisons = {n["module"]: n["raison"] for n in r["non_realises"]}
        self.assertIn("bug", raisons["D"])
        self.assertIn("abandonné", raisons["E"])
        # Fusion dans l'ordre demandé : a d'abord, b plus grave l'emporte et s'ajoute.
        constat = r["blocs"]["Exposition"]["constats"][0]
        self.assertEqual(constat["niveau"], IMPORTANT)
        self.assertEqual(constat["sources"], ["A", "B"])
        self.assertEqual({e["module"] for e in r["deroule"]}, set("abcde"))

    def test_indices_tires_du_site(self):
        from vigie import indices
        page = ('<a href="https://www.instagram.com/pavillon.noir/">Insta</a>'
                '<a href="https://www.facebook.com/sharer/sharer.php?u=x">partager</a>'
                '<a href="https://x.com/PavillonNoir">X</a>'
                '<a href="https://www.linkedin.com/company/pavillon-noir/">in</a>'
                "Tél. : 01 23 45 67 89 — portable +33 6 12 34 56 78")
        comptes = indices.reseaux_sociaux(page)
        self.assertEqual(comptes["instagram"], ["pavillon.noir"])
        self.assertNotIn("facebook", comptes)
        self.assertEqual(indices.numeros(page), ["+33123456789", "+33612345678"])
        self.assertEqual(indices.nom_dans_domaine("pavillon-noir.tech"), "pavillon-noir")
        self.assertEqual(indices.nom_dans_domaine("www.exemple.co.uk"), "exemple")
        indices._ouvrir = lambda url: page if url.endswith("ex.fr/") else None
        indices.oublier()
        self.assertEqual(indices.pseudos_societe("ex.fr"),
                         ["pavillon.noir", "pavillon-noir", "PavillonNoir"])
        indices.oublier()
        indices._ouvrir = pas_de_telechargement
        self.assertEqual(indices.pseudos_societe("ex.fr"), ["ex"])
        self.assertEqual(indices.numeros_publics("ex.fr"), [])

    def test_lecteurs_des_sorties(self):
        from vigie.modules import complet
        self.assertEqual(complet.lire_amass(
            "www.ex.fr (FQDN) --> a_record --> 1.2.3.4 (IPAddress)\nmail.ex.fr\nautre.fr\n"
            "pasex.fr", "ex.fr"), ["mail.ex.fr", "www.ex.fr"])
        fiches = complet.lire_dnsx('{"host":"a.ex.fr","a":["1.2.3.4"]}\n'
                                   '{"host":"vieux.ex.fr","cname":["x.herokuapp.com"]}\nbruit')
        self.assertEqual(fiches["vieux.ex.fr"], {"a": [], "cname": ["x.herokuapp.com"]})
        infos = complet.lire_whatweb([{"plugins": {
            "WordPress": {"version": ["6.4.2"]}, "Country": {}, "HTTPServer": {"string": ["nginx"]},
            "JQuery": {}}}])
        self.assertEqual(infos, {"technos": ["WordPress 6.4.2", "nginx", "JQuery"],
                                 "avec_version": 1})
        self.assertEqual(complet.lire_uncover("1.2.3.4:443\n[INF] bruit\nmail.ex.fr:25\n"
                                              "1.2.3.4:443"), ["1.2.3.4:443", "mail.ex.fr:25"])
        self.assertEqual(complet.lire_exiv2(
            "Exif.GPSInfo.GPSLatitude  Rational  3  48 deg\n"
            "Exif.Image.Artist  Ascii  10  Jean\n"), (True, True))
        self.assertEqual(complet.lire_exiv2("Exif.Image.Make  Ascii 6 Canon"), (False, False))
        self.assertEqual(complet.lire_instagram({"node": {
            "edge_followed_by": {"count": 120}, "is_private": False,
            "business_email": "a@b.fr"}})["abonnes"], 120)
        self.assertEqual(pseudos.lire_social_analyzer(
            'bruit {"detected": [{"link": "https://www.github.com/x"},'
            '{"link": "https://hudsonrock.com/x"}]}'),
            [{"site": "github.com", "adresse": "https://www.github.com/x"}])

    def test_dnsx_repere_les_alias_orphelins(self):
        from vigie.modules import complet
        recus = {}

        def faux(nom, arguments, delai=300, dossier=None, entree=None):
            recus["entree"] = entree
            return Fini('{"host":"ex.fr","a":["1.2.3.4"]}\n'
                        '{"host":"www.ex.fr","a":["1.2.3.4"]}\n'
                        '{"host":"boutique.ex.fr","cname":["shop.myshopify.com"]}\n')

        outils.executer_detail = faux
        cible = Cible("ex.fr", indices={
            "sousdomaines": {"sous_domaines": ["boutique.ex.fr", "test.ex.fr"]},
            "sousdomaines_amass": {"sous_domaines": ["test.ex.fr"]}})
        constats, brut = complet.analyser_dnsx(cible)
        self.assertEqual(recus["entree"].split(), ["ex.fr", "www.ex.fr", "boutique.ex.fr",
                                                   "test.ex.fr"])
        self.assertEqual(brut["alias_orphelins"], ["boutique.ex.fr"])
        self.assertEqual(brut["muets"], ["test.ex.fr"])
        self.assertEqual([c.niveau for c in constats], [IMPORTANT, INFO])

    def test_uncover_sans_cle_explique(self):
        from vigie.modules import complet
        outils.executer_detail = lambda *a, **k: Fini("", "[FTL] no keys provided")
        with self.assertRaises(ControleImpossible) as refus:
            complet.analyser_uncover(Cible("ex.fr"))
        self.assertIn("clé d'accès", str(refus.exception))

    def test_numeros_jamais_dans_le_rapport(self):
        from vigie import indices
        from vigie.modules import complet
        indices._ouvrir = lambda url: "Appelez le 06 12 34 56 78"
        outils.executer = lambda *a, **k: "Country: FR\nLocal: 06 12 34 56 78\n"
        constats, brut = complet.analyser_phoneinfoga(Cible("ex.fr"))
        texte = json.dumps([c.en_dict() for c in constats] + [brut], ensure_ascii=False)
        self.assertNotIn("12 34", texte)
        self.assertNotIn("612345678", texte)
        self.assertEqual(brut["numeros"][0]["portable"], True)

    def test_rapport_montre_les_42(self):
        with mock.patch.object(outils, "trouver", return_value=None):
            r = cli.lancer(Cible("ex.fr", "Essai"), ["mail", "photos", "pseudos_societe"],
                           date="2026-11-24")
        self.assertEqual(len(r["outils_diag"]), 42)
        page = rapport.en_html(r)
        self.assertIn("Les 42 outils du diagnostic gratuit", page)
        self.assertIn("Pi-hole", page)
        self.assertIn("Pas lançable ici", page)
        texte = rapport.en_texte(r)
        self.assertIn("Robin — Écarté par la règle légale", texte)
        self.assertNotIn("Les 42 outils", rapport.en_html(r, public="executif"))
        # Le diagnostic rapide ne change pas.
        r = cli.lancer(Cible("ex.fr"), ["mail"], date="2026-11-24")
        self.assertNotIn("outils_diag", r)

    def test_interface_lance_le_complet_par_defaut(self):
        from vigie.modules import COMPLET
        lances = {}

        def faux_suivi(ident, cible, noms, sortie):
            lances.update(cible=cible, noms=noms)

        with mock.patch.object(interface, "executer_suivi", faux_suivi):
            interface.traiter_formulaire("domaine=ex.fr&pseudo=jean&mail=j%40ex.fr", "x")
            time.sleep(0.1)
            self.assertEqual(lances["noms"], COMPLET)
            # Sans la case « accord », les données du dirigeant ne servent pas.
            self.assertEqual((lances["cible"].pseudos, lances["cible"].emails), ([], []))
            interface.traiter_formulaire(
                "domaine=ex.fr&formule=rapide&pseudo=jean&mail=j%40ex.fr&accord=oui", "x")
            time.sleep(0.1)
            self.assertEqual(lances["noms"], PAR_DEFAUT)
            self.assertEqual(lances["cible"].pseudos, ["jean"])
            self.assertTrue(lances["cible"].accord_dirigeant)
        self.assertIn('value="complet" checked', interface.page_accueil("inexistant"))

    def test_cli_complet(self):
        from vigie.modules import COMPLET
        recu = {}

        def faux_lancer(cible, noms, chemin=None):
            recu.update(cible=cible, noms=noms)
            return cli.rapport.construire("ex.fr", "ex.fr", "2026-11-24", [], {}, [], None)

        with mock.patch.object(cli, "lancer", faux_lancer), \
                tempfile.TemporaryDirectory() as sortie, \
                mock.patch("builtins.print"):
            cli.main(["diagnostic", "ex.fr", "--complet", "--sortie", sortie,
                      "--mail", "j@ex.fr"])
        self.assertEqual(recu["noms"], COMPLET)
        # Avant, l'adresse du dirigeant atterrissait dans la mauvaise case (bug corrigé).
        self.assertEqual(recu["cible"].emails, ["j@ex.fr"])


class Fiabilite(Base):
    """Diagnostic complet du 24/11/2026 sur pavillon-noir.tech (VM Ubuntu derrière un
    pare-feu de labo) : faux positifs, outils muets en 0 s, outils trop longs."""

    def test_https_repond_oui_non_inconnu(self):
        reseau.https_repond = self._sauve_https
        vrai = reseau._poignee_tls
        self.addCleanup(setattr, reseau, "_poignee_tls", vrai)
        reseau._poignee_tls = lambda hote, delai: True
        self.assertEqual(reseau.https_repond("ex.fr"), reseau.OUI)

        def refus(hote, delai):
            raise ConnectionRefusedError()
        reseau._poignee_tls = refus
        self.assertEqual(reseau.https_repond("ex.fr"), reseau.NON)

        def en_clair(hote, delai):
            raise ssl.SSLError("[SSL: WRONG_VERSION_NUMBER] wrong version number")
        reseau._poignee_tls = en_clair
        self.assertEqual(reseau.https_repond("ex.fr"), reseau.NON)

        def lent(hote, delai):
            raise TimeoutError("timed out")
        reseau._poignee_tls = lent
        self.assertEqual(reseau.https_repond("ex.fr"), reseau.INCONNU)
        # Un essai lent puis un refus : pas de conclusion.
        reponses = iter([TimeoutError(), ConnectionRefusedError()])

        def melange(hote, delai):
            raise next(reponses)
        reseau._poignee_tls = melange
        self.assertEqual(reseau.https_repond("ex.fr"), reseau.INCONNU)

    def test_sslyze_reessaie_puis_dit_que_le_site_repond(self):
        appels = []
        echec = {"server_scan_results": [{"connectivity_status": "ERROR",
                                          "connectivity_error_trace": "Traceback\nTimeout"}]}

        def faux(nom, arguments, **k):
            appels.append(nom)
            return ecrit_fichier("--json_out", echec)(nom, arguments)
        outils.executer = faux
        reseau.https_repond = lambda *a, **k: reseau.OUI
        with self.assertRaises(ControleImpossible) as empechement:
            chiffrement.analyser(CIBLE)
        self.assertEqual(appels, ["sslyze", "sslyze"])          # 2 essais
        self.assertIn("répond bien en connexion chiffrée", str(empechement.exception))
        self.assertIn("Timeout", str(empechement.exception))

    def test_sslyze_deuxieme_essai_reussi(self):
        reussite = LotDix.SSLYZE
        echec = {"server_scan_results": [{"connectivity_status": "ERROR"}]}
        reponses = iter([echec, reussite])
        outils.executer = lambda nom, arguments, **k: ecrit_fichier(
            "--json_out", next(reponses))(nom, arguments)
        constats, _ = chiffrement.analyser(CIBLE)
        self.assertIn("certificat", {c.cle for c in constats})

    def test_whatweb_dit_pourquoi(self):
        from vigie.modules import complet
        appels = []

        def faux(nom, arguments, **k):
            appels.append(arguments)
            return resultat("", "/usr/share/whatweb/lib/x.rb: undefined method `exists?' "
                                "for File:Class", 1)
        outils.executer_detail = faux
        reseau.https_repond = lambda *a, **k: reseau.OUI
        with self.assertRaises(ControleImpossible) as empechement:
            complet.analyser_whatweb(CIBLE)
        self.assertEqual(len(appels), 2)
        self.assertNotIn("--no-errors", appels[0])
        message = str(empechement.exception)
        self.assertIn("répond bien", message)
        self.assertIn("Ruby", message)
        self.assertNotIn("injoignable", message)

    def test_dnsrecon_repli_sur_le_dns_de_la_machine(self):
        appels = []
        fiches = [{"type": "AAAA", "address": "2001:db8::1"}]

        def faux(nom, arguments, **k):
            appels.append(list(arguments))
            if "-n" in arguments:
                return resultat("[-] Could not resolve domain: ex.fr\n", "", 1)
            return ecrit_fichier("-j", fiches)(nom, arguments) or resultat()
        outils.executer_detail = faux
        from vigie.modules import complements
        constats, brut = complements.analyser_dns(CIBLE)
        self.assertEqual(len(appels), 2)
        self.assertNotIn("-n", appels[1])
        self.assertEqual(brut["dns_complet"]["ipv6"], ["2001:db8::1"])

    def test_dnsrecon_raison_en_francais(self):
        outils.executer_detail = lambda *a, **k: resultat(
            "[-] Could not resolve domain: ex.fr\n", "", 1)

        def dns_coupe(nom, typ):
            raise reseau.ErreurReseau("DNS injoignable")
        reseau.dns = dns_coupe  # Vigie non plus ne peut pas lire la fiche : pas de repli
        from vigie.modules import complements
        with self.assertRaises(ControleImpossible) as empechement:
            complements.analyser_dns(CIBLE)
        self.assertIn("pare-feu", str(empechement.exception))
        self.assertNotIn("Could not", str(empechement.exception))

    def test_linkchecker_borne_en_temps_et_en_liens(self):
        from vigie.modules import liens
        vus = {}

        def faux(nom, arguments, delai=0, dossier=None, partiel=False):
            with open(arguments[arguments.index("-f") + 1], encoding="utf-8") as lu:
                vus["reglages"] = lu.read()
            vus.update(delai=delai, partiel=partiel)
            return LotDeux.LINKCHECKER
        outils.executer = faux
        constats, brut = liens.analyser(CIBLE)
        self.assertIn("maxrunseconds=240", vus["reglages"])
        self.assertIn("maxnumurls=400", vus["reglages"])
        self.assertTrue(vus["partiel"])
        # LinkChecker s'arrête seul à 4 min : le délai de Vigie passe après, et le
        # contrôle tient dans son propre délai (modules/__init__.py).
        self.assertGreater(vus["delai"], 240)
        self.assertGreater(MODULES["liens"]["delai"], vus["delai"])
        self.assertIn("liens_casses", {c.cle for c in constats})

    def test_resultat_partiel_garde_a_l_expiration(self):
        vrai = subprocess.run

        def trop_long(*a, **k):
            raise subprocess.TimeoutExpired(a[0], 1, output=b"[+] GitHub: https://github.com/x\n")
        outils_trouver = outils.trouver
        self.addCleanup(setattr, outils, "trouver", outils_trouver)
        outils.trouver = lambda commande: "/bin/true"
        with mock.patch.object(subprocess, "run", trop_long):
            fini = outils.executer_detail("sherlock", ["x"], delai=1, partiel=True)
            with self.assertRaises(ControleImpossible):
                outils.executer_detail("sherlock", ["x"], delai=1)
        self.assertIsNone(fini.returncode)
        self.assertIn("github.com/x", fini.stdout)
        self.assertIs(subprocess.run, vrai)

    def test_outils_de_pseudo_en_parallele_et_bornes(self):
        import threading as fils
        demarres, tous_la = [], fils.Barrier(3, timeout=5)

        def outil(nom, comptes):
            def lancer(pseudo):
                demarres.append(nom)
                tous_la.wait()  # bloque si les outils tournaient l'un après l'autre
                if comptes is None:
                    raise ControleImpossible("l'outil maigret n'a pas répondu en 300 secondes")
                return comptes
            return lancer
        par_outil, ecartes = pseudos.lancer_ensemble("ex", [
            ("Sherlock", outil("Sherlock", [{"site": "GitHub", "adresse": "a"}])),
            ("Maigret", outil("Maigret", None)),
            ("user-scanner", outil("user-scanner", [{"site": "github", "adresse": "a"}]))])
        self.assertEqual(sorted(demarres), ["Maigret", "Sherlock", "user-scanner"])
        self.assertEqual(list(par_outil), ["Sherlock", "user-scanner"])
        self.assertIn("300 secondes", ecartes["Maigret"])
        self.assertLessEqual(pseudos.DELAI_OUTIL, 300)
        self.assertLessEqual(MODULES["pseudos_societe"]["delai"], 1000)


class Recettes(unittest.TestCase):
    """Installation sous Ubuntu des outils que la doc fait rater (24/11/2026)."""

    def test_recettes_prevues(self):
        from vigie import recettes
        for nom in ("EyeWitness", "Metagoofil", "uncover", "sitespeed.io", "Unlighthouse",
                    "PhoneInfoga", "dnstwist"):
            self.assertIsNotNone(recettes.pour(nom, "linux"), nom)
        self.assertIsNone(recettes.pour("nmap", "linux"))
        self.assertIn("uncover", recettes.GRATUITS_MALGRE_CLE)

    def test_plus_de_sudo_apt_eyewitness_sous_linux(self):
        for nom in ("eyewitness", "metagoofil", "sitespeed.io", "unlighthouse", "phoneinfoga"):
            astuce = outils.astuce_installation(nom, systeme="linux")
            self.assertNotIn("apt", astuce, nom)
            self.assertIn("installeur Linux de Vigie", astuce)

    def test_empreintes(self):
        from vigie import recettes
        sommes = recettes.lire_sommes(
            "6173dfc4ec009a6fe688068bac5a250646f5a8f56409098f5edcc7e404b12a52  "
            "phoneinfoga_Linux_x86_64.tar.gz\nligne sans intérêt\n")
        self.assertEqual(list(sommes), ["phoneinfoga_Linux_x86_64.tar.gz"])

    def test_extraction_ne_sort_jamais_du_dossier(self):
        import io
        import tarfile
        from vigie import recettes
        with tempfile.TemporaryDirectory() as dossier:
            archive = os.path.join(dossier, "a.tar.gz")
            with tarfile.open(archive, "w:gz") as tar:
                for nom, contenu in (("node-v22/bin/node", b"ok"), ("node-v22/../../piege", b"x")):
                    info = tarfile.TarInfo(nom)
                    info.size = len(contenu)
                    tar.addfile(info, io.BytesIO(contenu))
            recettes._extraire_tout(archive, os.path.join(dossier, "node22"))
            self.assertTrue(os.path.exists(os.path.join(dossier, "node22", "bin", "node")))
            self.assertFalse(os.path.exists(os.path.join(dossier, "piege")))

    def test_recette_passe_avant_la_doc_et_la_doc_reste_en_secours(self):
        from vigie import installeur, recettes
        vrais = (dict(recettes.RECETTES), installeur.repond, installeur._installer_par_doc)
        self.addCleanup(lambda: (recettes.RECETTES.clear(), recettes.RECETTES.update(vrais[0]),
                                 setattr(installeur, "repond", vrais[1]),
                                 setattr(installeur, "_installer_par_doc", vrais[2])))
        installeur.repond = lambda binaire, delai=25: binaire == "eyewitness"
        installeur._installer_par_doc = lambda outil, a_blanc=False, devines=True: {
            "nom": outil["nom"], "installe": False, "repond": False, "binaire": "",
            "methode": "", "raison": "apt (documenté) : Unable to locate package eyewitness"}
        recettes.RECETTES["eyewitness"] = ("recette", lambda: (True, "", ["eyewitness"]),
                                           recettes.TOUS)
        compte = installeur.installer_un({"nom": "EyeWitness",
                                          "lien": "https://github.com/RedSiege/EyeWitness"})
        self.assertEqual((compte["installe"], compte["repond"], compte["methode"]),
                         (True, True, "recette"))
        recettes.RECETTES["eyewitness"] = ("recette", lambda: (False, "git : refusé", []),
                                           recettes.TOUS)
        compte = installeur.installer_un({"nom": "EyeWitness",
                                          "lien": "https://github.com/RedSiege/EyeWitness"})
        self.assertFalse(compte["installe"])
        self.assertIn("git : refusé", compte["raison"])
        self.assertIn("Unable to locate", compte["raison"])

    def test_lanceur_executable(self):
        from vigie import recettes
        with tempfile.TemporaryDirectory() as dossier:
            chemin = os.path.join(dossier, "bin", "outil")
            recettes.ecrire_lanceur(chemin, ['exec echo "bonjour $@"'])
            sortie = subprocess.run([chemin, "Anass"], capture_output=True, text=True).stdout
        self.assertEqual(sortie.strip(), "bonjour Anass")

    def test_node_trop_vieux_pose_node_22_a_part(self):
        from vigie import recettes
        appels = []
        vrais = (recettes.version_node, recettes.node_a_part, recettes._lancer)
        self.addCleanup(lambda: (setattr(recettes, "version_node", vrais[0]),
                                 setattr(recettes, "node_a_part", vrais[1]),
                                 setattr(recettes, "_lancer", vrais[2])))
        recettes.version_node = lambda commande="node": 18   # Ubuntu 24.04
        with tempfile.TemporaryDirectory() as dossier:
            recettes.node_a_part = lambda: (os.path.join(dossier, "node22", "bin"), "")
            recettes._lancer = lambda commande, **k: appels.append(commande) or (True, "", "")
            with mock.patch.dict(os.environ, {"VIGIE_OUTILS_RACINE": dossier,
                                              "PIPX_BIN_DIR": os.path.join(dossier, "bin")}):
                reussi, _, binaires = recettes.pour("sitespeed.io", "linux")[1]()
            self.assertTrue(reussi)
            self.assertIn("--prefix", appels[0])
            self.assertTrue(appels[0][0].endswith(os.path.join("node22", "bin", "npm")))
            with open(os.path.join(dossier, "bin", "sitespeed.io"), encoding="utf-8") as lu:
                self.assertIn("node22", lu.read())

class TableFailles(unittest.TestCase):
    """La table F01-F34 d'Anass branchée sur l'onglet Conséquences (26/11/2026)."""

    def test_le_json_et_les_csv_disent_la_meme_chose(self):
        import csv
        from vigie import failles
        table = failles.failles()
        self.assertEqual(sorted(table), [f"F{i:02d}" for i in range(1, 35)])
        with open(os.path.join(failles.DOSSIER, "pavillon-noir-failles-consequences.csv"),
                  encoding="utf-8-sig", newline="") as lu:
            lignes = list(csv.DictReader(lu, delimiter=";"))
        self.assertEqual(len(lignes), 34)
        for ligne in lignes:
            for colonne in failles.COLONNES_CLIENT:
                self.assertEqual(ligne[colonne], table[ligne["id"]][colonne],
                                 f"{ligne['id']} / {colonne}")
        with open(os.path.join(failles.DOSSIER, "pavillon-noir-cas-reels.csv"),
                  encoding="utf-8-sig", newline="") as lu:
            cas = {c["id"]: c for c in csv.DictReader(lu, delimiter=";")}
        for cid, c in failles.cas_reels().items():
            self.assertEqual(cas[cid]["fiabilite"], c["fiabilite"])

    def test_chaque_correspondance_vise_une_faille_qui_existe(self):
        from vigie import consequences, failles
        table = failles.failles()
        for cle, regles in failles.CORRESPONDANCE.items():
            for _, fid in regles:
                self.assertIn(fid, table, cle)
            if not cle.startswith("assureur_"):
                self.assertIn(cle, consequences.CONSEQUENCES, cle)

    def test_dmarc_absent_et_p_none_ne_sont_pas_la_meme_faille(self):
        from vigie import failles
        absent = {"cle": "dmarc", "titre": "Aucune consigne contre l'usurpation (DMARC absent)"}
        surveillance = {"cle": "dmarc", "titre": "DMARC en simple surveillance (p=none)"}
        quarantaine = {"cle": "dmarc", "titre": "DMARC en quarantaine, pas encore en blocage"}
        self.assertEqual(failles.identifiant(absent), "F04")
        self.assertEqual(failles.identifiant(surveillance), "F05")
        self.assertEqual(failles.identifiant(quarantaine), "")
        sosie = {"cle": "domaines_imitateurs", "titre": "3 domaines imitent le vôtre",
                 "explication": "Dont 1 capables de recevoir du courrier."}
        self.assertEqual(failles.identifiant(sosie), "F11")
        self.assertEqual(failles.identifiant({"cle": "https_www.ex.fr"}), "F17")

    def test_garde_fous(self):
        from vigie import failles
        table = failles.failles()
        # Jamais la phrase pour le téléphone ni les colonnes d'entraînement.
        fiche = failles.pour({"cle": "spf", "titre": "SPF absent"})
        for colonne in failles.COLONNES_ENTRAINEMENT:
            self.assertNotIn(colonne, fiche)
        # Seulement les cas « forte ».
        tous = failles.cas_reels()
        forts = {c["titre"] for c in tous.values() if c["fiabilite"] == "forte"}
        for cle in failles.CORRESPONDANCE:
            for cas in failles.pour({"cle": cle, "titre": "absent 3389 445"}, True).get("cas", []):
                self.assertIn(cas["titre"], forts)
        # Case C : cachée sans autorisation, montrée avec.
        mfa = {"cle": "assureur_mfa_distance", "titre": "x"}
        self.assertEqual(failles.pour(mfa, autorise=False), {})
        self.assertEqual(failles.pour(mfa, autorise=True)["id"], "F07")
        # Fuites : jamais à froid, même marquées « A » dans la table.
        for fid in failles.FUITES:
            self.assertFalse(failles.montrable(table[fid], autorise=False))
        self.assertFalse(failles.montrable(table["F33"], autorise=True))   # à construire

    def test_le_rapport_n_affiche_jamais_la_phrase_telephone(self):
        from vigie import failles
        constats = [Constat("Exposition", CRITIQUE, f"x {cle}", "absent 3389 445", "y", cle=cle)
                    for cle in failles.CORRESPONDANCE]
        signee = {"fichier": "a.pdf", "empreinte_sha256": "0" * 64}
        r = rapport.construire("S", "ex.fr", "2026-11-26", constats, {}, [], signee)
        sorties = [rapport.en_html(r), rapport.en_texte(r), json.dumps(r, ensure_ascii=False)]
        try:
            sorties.append(rapport.en_html(r, public="executif"))
        except TypeError:
            pass
        for faille in failles.failles().values():
            for colonne in ("phrase_telephone", "place_dans_l_offre"):
                if faille.get(colonne):
                    for sortie in sorties:
                        self.assertNotIn(faille[colonne], sortie, faille["id"])
        self.assertIn("Faille F04", sorties[0])
        self.assertIn("Faille F07", sorties[0])   # autorisation signée : la case C apparaît
        sans = rapport.en_html(rapport.construire("S", "ex.fr", "2026-11-26", constats, {}, [],
                                                  None))
        self.assertNotIn("Faille F07", sans)


class Consequences(unittest.TestCase):
    """L'onglet « Conséquences » : attaquant, entreprise, loi, assurance (24/11/2026)."""

    def test_chaque_cle_de_constat_a_ses_consequences(self):
        from vigie import consequences
        from vigie.questionnaire import QUESTIONS
        dossier = os.path.join(os.path.dirname(__file__), "..", "vigie")
        cles = set()
        for racine, _, fichiers in os.walk(dossier):
            for nom in fichiers:
                if nom.endswith(".py"):
                    with open(os.path.join(racine, nom), encoding="utf-8") as f:
                        cles |= set(re.findall(r'cle\s*=\s*"([a-z0-9_]+)"(?!\s*\+)', f.read()))
        # clés qui ne portent QUE des constats « Correct » : rien à expliquer
        seulement_ok = {"lighthouse", "archive_page", "metadonnees", "archives", "liens"}
        manquantes = sorted(c for c in cles - seulement_ok
                            if c not in consequences.CONSEQUENCES)
        self.assertEqual(manquantes, [])
        for question in QUESTIONS:
            if question["id"] != "prestataire_securite":   # « non » n'y est pas un défaut
                self.assertIn(question["id"], consequences.CONSEQUENCES_ASSUREUR)
        for cle in ("spf", "dmarc", "dkim", "mx", "marque"):
            self.assertIn(cle, consequences.CONSEQUENCES)

    def test_constat_sans_cle_reconnu_par_son_titre(self):
        from vigie import consequences
        constat = {"niveau": IMPORTANT, "cle": "", "titre": "vieux.ex.fr n'est pas chiffré"}
        self.assertIn("attaquant", consequences.pour(constat))
        marque = {"niveau": INFO, "cle": "marque_ex", "titre": "x"}
        self.assertIn("attaquant", consequences.pour(marque))

    def test_un_constat_correct_n_a_pas_de_consequences(self):
        from vigie import consequences
        self.assertEqual(consequences.pour({"niveau": OK, "cle": "hsts", "titre": "x"}), {})

    def test_questionnaire_assureur_rappelle_la_fausse_declaration(self):
        from vigie import consequences
        fiche = consequences.pour({"niveau": CRITIQUE, "cle": "assureur_mfa_distance",
                                   "titre": "x"})
        self.assertIn("L.113-9", fiche["assurance"])

    def test_ton_mesure_et_sources(self):
        from vigie import consequences
        fiches = list(consequences.CONSEQUENCES.values()) \
            + list(consequences.CONSEQUENCES_ASSUREUR.values())
        for fiche in fiches:
            self.assertTrue(set(fiche) <= {nom for nom, _ in consequences.RUBRIQUES})
            for texte in fiche.values():
                # aucun montant d'amende par constat : les plafonds sont dans le cadre général
                self.assertNotIn("amende", texte.lower())
                self.assertNotIn("vous allez", texte.lower())
        for exemple in consequences.EXEMPLES.values():
            self.assertTrue(exemple["url"].startswith("https://"))
            self.assertTrue(exemple["source"] and exemple["texte"])
        cadre = " ".join(consequences.CADRE_GENERAL["points"])
        for texte in ("art. 32", "art. 33", "art. 83", "226-17", "NIS2", "L.12-10-1"):
            self.assertIn(texte, cadre)

    def _rapport(self, constats):
        return rapport.construire("S", "ex.fr", "2026-11-24", constats, {}, [], None)

    def test_le_rapport_porte_les_onglets(self):
        hsts = Constat("Exposition", IMPORTANT, "HSTS absent", "x", "Ajouter l'en-tête.",
                       cle="hsts")
        bon = Constat("Exposition", OK, "Certificat valide", "x", cle="certificat")
        r = self._rapport([hsts, bon])
        donnees = r["blocs"]["Exposition"]["constats"]
        self.assertIn("Wi-Fi", donnees[0]["consequences"]["attaquant"])
        self.assertEqual(donnees[1]["consequences"], {})
        technique = rapport.en_html(r)
        self.assertIn(">Conséquences</label>", technique)
        self.assertIn(">À corriger (technique)</label>", technique)
        self.assertIn("prestataire", technique)
        self.assertIn("Ce que disent la loi et les assureurs", technique)
        executif = rapport.en_html(r, public="executif")
        self.assertIn("Les conséquences, point par point", executif)
        texte = rapport.en_texte(r, public="executif")
        self.assertIn("LES CONSÉQUENCES, POINT PAR POINT", texte)
        self.assertIn("Ce qu'un attaquant peut faire", rapport.en_texte(r))

    def test_ancien_rapport_sans_consequences_s_affiche(self):
        r = self._rapport([Constat("Exposition", IMPORTANT, "t", "x", "y", cle="hsts")])
        for constat in r["blocs"]["Exposition"]["constats"]:
            del constat["consequences"]
        self.assertIn(">Conséquences</label>", rapport.en_html(r))

    def test_exemple_reel_affiche_avec_sa_source(self):
        r = self._rapport([Constat("Exposition", CRITIQUE, "DMARC absent", "x", "y",
                                   cle="dmarc")])
        html_ = rapport.en_html(r)
        self.assertIn("Exemple réel", html_)
        self.assertIn("cybermalveillance", html_.lower())


class Verdict(unittest.TestCase):
    """La phrase d'en-tête suit la lettre : un D n'est jamais rassurant (24/11/2026)."""

    def _verdict(self, constats):
        r = rapport.construire("S", "ex.fr", "2026-11-24", constats, {}, [], None)
        return r, rapport._verdict(r)

    def test_un_d_sans_critique_dit_qu_il_faut_agir(self):
        importants = [Constat("Exposition", IMPORTANT, f"p{i}", "x", cle=f"k{i}")
                      for i in range(4)] + [Constat("Exposition", INFO, "i", "x", cle="i")]
        r, verdict = self._verdict(importants)          # 100 - 40 - 2 = 58 -> D
        self.assertEqual(rapport._lettre(r["note_globale"]), "D")
        self.assertNotIn("Pas de", verdict)
        self.assertIn("exposée", verdict)
        strat = rapport._strategie_bloc(r["blocs"]["Exposition"])
        self.assertNotIn("Pas de critique", strat)
        self.assertIn("rapidement", strat)

    def test_un_b_rassure(self):
        _, verdict = self._verdict([Constat("Exposition", IMPORTANT, f"p{i}", "x", cle=f"k{i}")
                                    for i in range(2)])          # 80 -> B
        self.assertIn("Bon niveau", verdict)

    def test_une_critique_l_emporte_sur_une_bonne_note(self):
        _, verdict = self._verdict([Constat("Exposition", CRITIQUE, "p", "x", cle="k")])
        self.assertIn("critique", verdict)
        self.assertIn("sans attendre", verdict)


class TestInstalleurLinux25Novembre(unittest.TestCase):
    """Corrections après l'installation complète sur la VM Ubuntu (25/11/2026)."""

    def test_jamais_le_paquet_git_tire_d_une_adresse(self):
        from vigie import installeur
        essais = installeur.methodes(
            {"nom": "Impacket", "lien": "https://github.com/fortra/impacket"},
            install="pip install impacket ; pipx install git+https://github.com/fortra/impacket")
        commandes = [c for _, c in essais]
        self.assertIn(["pipx", "install", "impacket"], commandes)
        self.assertNotIn(["pipx", "install", "git"], commandes)

    def test_apt_un_par_un(self):
        from vigie import installeur
        en_cours, maximum, verrou = [0], [0], threading.Lock()

        def faux_run(*a, **k):
            with verrou:
                en_cours[0] += 1
                maximum[0] = max(maximum[0], en_cours[0])
            time.sleep(0.05)
            with verrou:
                en_cours[0] -= 1
            return subprocess.CompletedProcess(a[0], 0, "", "")
        commande = installeur.DOCUMENTEES[-1][2] + ["nmap"]
        with mock.patch.object(installeur.shutil, "which", return_value="/usr/bin/sudo"), \
                mock.patch.object(installeur.subprocess, "run", side_effect=faux_run):
            fils = [threading.Thread(target=installeur._lancer, args=(commande,))
                    for _ in range(5)]
            for f in fils:
                f.start()
            for f in fils:
                f.join()
        self.assertEqual(maximum[0], 1)

    def test_outil_a_la_main_pas_essaye_et_compte_a_part(self):
        from vigie import installeur
        with mock.patch.object(installeur, "_lancer") as lancer:
            compte = installeur.installer_un(
                {"nom": "geo-sleuth", "lien": "https://github.com/Oldcircle/geo-sleuth"})
        lancer.assert_not_called()
        self.assertTrue(compte["manuel"])
        self.assertIn("à la main", compte["raison"])
        bilan = installeur.resume([compte, {"nom": "X", "installe": False, "raison": "go"}])
        self.assertEqual((bilan["a_la_main"], bilan["vrais_echecs"]), (1, 1))

    def test_recettes_et_manuels_existent_dans_le_catalogue(self):
        from vigie import installeur, recettes
        noms = {o["nom"].lower() for o in installeur.charger()}
        for nom in list(recettes.RECETTES) + list(recettes.MANUELS):
            self.assertIn(nom, noms)
        self.assertFalse(set(recettes.RECETTES) & set(recettes.MANUELS))

    def test_pipx_retente_avec_python_de_secours(self):
        from vigie import installeur
        appels = []

        def faux_lancer(commande, delai=600):
            appels.append(commande)
            if "--python" in commande:
                return True, "", "installed package nettacker 1.0\n  These apps are now " \
                                 "globally available\n    - nettacker\n"
            return False, "Error installing nettacker.", "Error installing nettacker."
        with mock.patch.object(installeur, "_lancer", side_effect=faux_lancer), \
                mock.patch.object(installeur, "repond", side_effect=lambda b: b == "nettacker"):
            compte = installeur._installer_par_doc(
                {"nom": "OWASP Nettacker", "lien": "https://github.com/OWASP/Nettacker"})
        self.assertTrue(compte["repond"])
        self.assertIn("Python 3.12", compte["methode"])
        self.assertIn("--fetch-missing-python", appels[1])

    def test_un_outil_lent_a_demarrer_a_bien_demarre(self):
        from vigie import installeur
        with mock.patch.object(installeur.shutil, "which", return_value="/bin/garak"), \
                mock.patch.object(installeur.subprocess, "run",
                                  side_effect=subprocess.TimeoutExpired("garak", 60)):
            self.assertTrue(installeur.repond("garak"))

    def test_une_trace_python_n_est_pas_une_aide(self):
        from vigie import installeur
        trace = ("Traceback (most recent call last):\n  File \"x\", line 1\n"
                 "ModuleNotFoundError: No module named 'pkg_resources'\n")
        with mock.patch.object(installeur.shutil, "which", return_value="/bin/x"), \
                mock.patch.object(installeur.subprocess, "run",
                                  return_value=subprocess.CompletedProcess([], 1, "", trace)):
            self.assertFalse(installeur.repond("x"))
            self.assertIn("pkg_resources", installeur.erreur_demarrage(["x"]))

    def test_erreur_npm_lisible(self):
        from vigie import recettes
        sortie = ("npm ERR! code EACCES\nnpm ERR! syscall mkdir\nnpm ERR! path /usr/lib/x\n"
                  "npm ERR! A complete log of this run can be found in:\n"
                  "npm ERR!     /home/a/.npm/_logs/2026-debug-0.log\n")
        self.assertIn("EACCES", recettes.erreur_npm(sortie))
        self.assertNotIn("debug-0.log", recettes.erreur_npm(sortie))

    def test_noms_des_programmes_officiels(self):
        from vigie import recettes
        valeurs = dict(recettes.NOMS_SYSTEME["linux"], **recettes.NOMS_ARCH["x64"],
                       version="0.58.1")
        self.assertEqual("trivy_{version}_{mac}-{bits}.tar.gz".format(**valeurs),
                         "trivy_0.58.1_Linux-64bit.tar.gz")
        self.assertEqual("grype_{version}_{os}_{goarch}.tar.gz".format(**valeurs),
                         "grype_0.58.1_linux_amd64.tar.gz")

    def test_compte_rendu_vide_ne_fait_pas_planter(self):
        with tempfile.TemporaryDirectory() as dossier:
            chemin = os.path.join(dossier, "vigie-installation.json")
            open(chemin, "w").close()
            self.assertEqual(cli.lire_bilan(chemin), {})
            cli.ecrire_bilan(chemin, {"resume": {}, "details": []})
            self.assertEqual(cli.lire_bilan(chemin), {"resume": {}, "details": []})
            self.assertEqual(os.listdir(dossier), ["vigie-installation.json"])


class TestInstalleurSobreEnMemoire(unittest.TestCase):
    """26/11/2026 : Ubuntu a tué l'installeur (mémoire pleine) avec 6 installations de front."""

    def tearDown(self):
        from vigie import recettes
        recettes.regler_compilations(1)

    def test_parallele_suit_la_memoire(self):
        from vigie import recettes
        self.assertEqual(recettes.parallele_auto(1000), 1)
        self.assertEqual(recettes.parallele_auto(2500), 1)
        self.assertEqual(recettes.parallele_auto(4000), 2)
        self.assertEqual(recettes.parallele_auto(64000), recettes.PARALLELE_MAX)
        self.assertLessEqual(recettes.PARALLELE_MAX, 4)

    def test_option_parallele(self):
        with mock.patch("vigie.recettes.memoire_libre_mo", return_value=3000):
            self.assertEqual(cli.nombre_parallele("auto"), 2)
        self.assertEqual(cli.nombre_parallele("3"), 3)
        self.assertEqual(cli.nombre_parallele("-2"), 1)
        with self.assertRaises(SystemExit):
            cli.nombre_parallele("beaucoup")

    def test_compilations_reconnues(self):
        from vigie import recettes
        self.assertTrue(recettes.est_compilation(["pipx", "install", "x"]))
        self.assertTrue(recettes.est_compilation(["/opt/x/vigie-venv/bin/pip", "install"]))
        self.assertTrue(recettes.est_compilation(["go", "install", "a@latest"]))
        self.assertFalse(recettes.est_compilation(["sudo", "env", "apt-get"]))
        self.assertFalse(recettes.est_compilation(["npm", "install"]))

    def test_compilations_une_par_une(self):
        from vigie import installeur, recettes
        recettes.regler_compilations(1)
        en_cours, maximum, verrou = [0], [0], threading.Lock()

        def faux_run(*a, **k):
            with verrou:
                en_cours[0] += 1
                maximum[0] = max(maximum[0], en_cours[0])
            time.sleep(0.05)
            with verrou:
                en_cours[0] -= 1
            return subprocess.CompletedProcess(a[0], 0, "", "")
        with mock.patch.object(installeur.shutil, "which", return_value="/usr/bin/pipx"), \
                mock.patch.object(installeur.subprocess, "run", side_effect=faux_run), \
                mock.patch.object(recettes, "memoire_libre_mo", return_value=8000):
            fils = [threading.Thread(target=installeur._lancer, args=(["pipx", "install", "x"],))
                    for _ in range(5)]
            for f in fils:
                f.start()
            for f in fils:
                f.join()
        self.assertEqual(maximum[0], 1)

    def test_attend_la_memoire(self):
        from vigie import recettes
        lectures = iter([300, 400, 2000])
        with mock.patch.object(recettes, "memoire_libre_mo", side_effect=lambda: next(lectures)), \
                mock.patch.object(recettes.time, "sleep"):
            self.assertEqual(recettes.attendre_memoire(pause=5), 10)

    def test_compte_rendu_ecrit_apres_chaque_outil(self):
        from vigie import installeur
        vus = []
        with mock.patch.object(installeur, "installer_un",
                               side_effect=lambda o, a=False: {"nom": o["nom"], "installe": True,
                                                               "repond": True, "methode": "x",
                                                               "raison": ""}):
            installeur.installer([{"nom": "A"}, {"nom": "B"}, {"nom": "C"}],
                                 journal=lambda *a: None, parallele=2,
                                 apres_chaque=lambda c: vus.append(len(c)))
        self.assertEqual(vus, [1, 2, 3])


class TestBrancherALaMain(unittest.TestCase):
    """« Je l'ai installé à la main » : relier un outil posé par Anass (26/11/2026)."""

    def setUp(self):
        from vigie import a_la_main
        self.dossier = tempfile.mkdtemp()
        self.bin = os.path.join(self.dossier, "bin")
        os.makedirs(self.bin)
        self.rapport = os.path.join(self.dossier, "vigie-installation.json")
        self.patchs = [mock.patch.object(a_la_main, "dossier_commandes", return_value=self.bin),
                       mock.patch.dict(os.environ, {"PATH": self.bin + os.pathsep
                                                    + os.environ.get("PATH", "")})]
        for p in self.patchs:
            p.start()

    def tearDown(self):
        import shutil
        for p in self.patchs:
            p.stop()
        shutil.rmtree(self.dossier, ignore_errors=True)

    def _faux_outil(self, chemin):
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        with open(chemin, "w") as f:
            f.write("#!/bin/sh\necho 'Usage: chainsaw [options] <cmd> -- un faux outil pour le test'\n")
        os.chmod(chemin, 0o755)

    def test_programme_dans_un_dossier(self):
        from vigie import a_la_main
        self._faux_outil(os.path.join(self.dossier, "telecharge", "chainsaw"))
        message = a_la_main.brancher("Chainsaw", os.path.join(self.dossier, "telecharge"),
                                     rapport=self.rapport)
        self.assertIn("démarre bien", message)
        lanceur = os.path.join(self.bin, "chainsaw")
        self.assertTrue(os.access(lanceur, os.X_OK))
        with open(self.rapport) as f:
            details = json.load(f)["details"]
        self.assertEqual(details[0]["nom"], "Chainsaw")
        self.assertTrue(details[0]["repond"])
        self.assertEqual(details[0]["methode"], "installé à la main")

    def test_refus_clairs(self):
        from vigie import a_la_main
        with self.assertRaises(a_la_main.Refus):
            a_la_main.brancher("Chainsaw", "/nulle/part/chainsaw", rapport=self.rapport)
        with self.assertRaises(a_la_main.Refus):
            a_la_main.brancher("Outil inconnu", self.dossier, rapport=self.rapport)
        with self.assertRaises(a_la_main.Refus):
            a_la_main.brancher("Chainsaw", self.dossier + '/a"b', rapport=self.rapport)

    def test_ne_remplace_jamais_un_vrai_programme(self):
        from vigie import a_la_main
        self._faux_outil(os.path.join(self.bin, "chainsaw"))  # un vrai programme déjà là
        self._faux_outil(os.path.join(self.dossier, "x", "chainsaw"))
        with self.assertRaises(a_la_main.Refus):
            a_la_main.brancher("Chainsaw", os.path.join(self.dossier, "x", "chainsaw"),
                               rapport=self.rapport)

    def test_installeur_reconnait_un_outil_deja_pose(self):
        from vigie import installeur
        self._faux_outil(os.path.join(self.bin, "chainsaw"))
        with mock.patch.object(installeur, "_lancer") as lancer:
            compte = installeur.installer_un(
                {"nom": "Chainsaw", "lien": "https://github.com/WithSecureLabs/chainsaw"})
        lancer.assert_not_called()
        self.assertTrue(compte["installe"])
        self.assertEqual(compte["methode"], "installé à la main")

    def test_formulaire_dans_la_page(self):
        from vigie import interface_outils
        self.assertIn("/outil/brancher", interface_outils.page())


class TestInstalleurDisqueEtReparations(unittest.TestCase):
    """26/11/2026, 2e installation complète : promptfoo (ENOTEMPTY), Stratus Red Team
    (disque plein + module deviné), auto-archiver / Nebula / garak muets."""

    def setUp(self):
        self.dossier = tempfile.mkdtemp()
        self.racine = os.path.join(self.dossier, "vigie-outils")
        for sous in ("tmp", "cache/go-build", "cache/pip", "bin"):
            os.makedirs(os.path.join(self.racine, sous))
        self.env = mock.patch.dict(os.environ, {
            "VIGIE_OUTILS_RACINE": self.racine,
            "TMPDIR": os.path.join(self.racine, "tmp"),
            "GOCACHE": os.path.join(self.racine, "cache", "go-build"),
            "PIP_CACHE_DIR": os.path.join(self.racine, "cache", "pip"),
            "PIPX_BIN_DIR": os.path.join(self.racine, "bin")})
        self.env.start()

    def tearDown(self):
        import shutil
        self.env.stop()
        shutil.rmtree(self.dossier, ignore_errors=True)

    def _poser(self, *chemins):
        for chemin in chemins:
            chemin = os.path.join(self.racine, chemin)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w") as fichier:
                fichier.write("x")

    def test_menage_ne_touche_que_les_restes_de_vigie(self):
        from vigie import recettes
        dehors = os.path.join(self.dossier, "cache-perso")
        os.makedirs(dehors)
        open(os.path.join(dehors, "garde"), "w").close()
        self._poser("tmp/go-build123/a", "tmp/pip-req-build-x/b", "tmp/tmpabcdef12/c",
                    "cache/go-build/00/d", "cache/pip/http/e", "pipx/venvs/garak/f")
        with mock.patch.dict(os.environ, {"UV_CACHE_DIR": dehors}):
            recettes.faire_de_la_place()
        tmp = os.listdir(os.path.join(self.racine, "tmp"))
        self.assertEqual(tmp, ["tmpabcdef12"])  # pas un reste de compilateur : gardé
        self.assertEqual(os.listdir(os.path.join(self.racine, "cache", "go-build")), [])
        self.assertEqual(os.listdir(os.path.join(self.racine, "cache", "pip")), [])
        self.assertTrue(os.path.exists(os.path.join(dehors, "garde")))  # pas à Vigie
        self.assertTrue(os.path.exists(os.path.join(self.racine, "pipx/venvs/garak/f")))

    def test_restes_vides_au_depart_seulement_chez_vigie(self):
        from vigie import recettes
        self._poser("tmp/go-build1/a", "tmp/tmpxyz/b")
        recettes.nettoyer_restes()
        self.assertEqual(os.listdir(os.path.join(self.racine, "tmp")), [])
        systeme = os.path.join(self.dossier, "tmp-systeme")
        os.makedirs(os.path.join(systeme, "go-build9"))
        with mock.patch.dict(os.environ, {"TMPDIR": systeme}):
            recettes.nettoyer_restes()
            recettes.faire_de_la_place()
        self.assertEqual(os.listdir(systeme), ["go-build9"])

    def test_chantier_fait_le_menage_quand_personne_ne_compile(self):
        from vigie import recettes
        with mock.patch.object(recettes, "place_libre_mo", return_value=500), \
                mock.patch.object(recettes, "attendre_memoire"), \
                mock.patch.object(recettes, "faire_de_la_place") as menage, \
                mock.patch.object(recettes, "apres_go") as apres:
            with recettes.chantier(["pipx", "install", "garak"]):
                pass
            self.assertEqual(menage.call_count, 1)
            apres.assert_not_called()
            with recettes.chantier(["go", "install", "x@latest"]):
                pass
            apres.assert_called_once()
            menage.reset_mock()
            recettes.regler_compilations(2)
            try:
                with recettes.chantier(["go", "install", "a@latest"]):
                    with recettes.chantier(["pipx", "install", "b"]):
                        pass  # une autre compilation tourne : pas de ménage
                self.assertEqual(menage.call_count, 1)
            finally:
                recettes.regler_compilations(1)
        with mock.patch.object(recettes, "faire_de_la_place") as menage:
            with recettes.chantier(["npm", "install", "x"]):
                pass
        menage.assert_not_called()

    def test_apres_go_vide_le_cache_de_compilation(self):
        from vigie import recettes
        self._poser("tmp/go-build5/a", "tmp/pip-x/b", "cache/go-build/ab/c")
        recettes.apres_go()
        self.assertEqual(os.listdir(os.path.join(self.racine, "tmp")), ["pip-x"])
        self.assertEqual(os.listdir(os.path.join(self.racine, "cache", "go-build")), [])

    def test_npm_enotempty_retire_le_reste_et_reessaie(self):
        from vigie import recettes
        modules = os.path.join(self.racine, "node-outils", "lib", "node_modules")
        self._poser("node-outils/lib/node_modules/promptfoo/package.json",
                    "node-outils/lib/node_modules/.promptfoo-q6tZKrsN/x",
                    "node-outils/lib/node_modules/lighthouse/package.json")
        reponses = iter([(False, "npm ERR! code ENOTEMPTY",
                          "npm ERR! code ENOTEMPTY\nnpm ERR! syscall rename\n"),
                         (True, "", "added 1 package")])
        vus = []

        def faux(commande, env=None, **k):
            vus.append(sorted(os.listdir(modules)))
            return next(reponses)
        with mock.patch.object(recettes, "version_node", return_value=22), \
                mock.patch.object(recettes.shutil, "which", return_value="/usr/bin/node"), \
                mock.patch.object(recettes, "_lancer", side_effect=faux), \
                mock.patch.object(recettes, "ecrire_lanceur"):
            reussi, message, poses = recettes.installer_npm("promptfoo", ["promptfoo"])
        self.assertTrue(reussi, message)
        self.assertEqual(vus[1], ["lighthouse"])  # seulement le reste de promptfoo retiré

    def test_pas_de_module_devine_apres_une_recette(self):
        from vigie import installeur, recettes
        lances = []

        def recette():
            return False, "github.com/spf13/cobra: no space left on device", []
        outil = {"nom": "Stratus Red Team", "lien": "https://github.com/DataDog/stratus-red-team"}
        with mock.patch.object(recettes, "pour", return_value=("go (documenté)", recette)), \
                mock.patch.object(installeur, "_lancer",
                                  side_effect=lambda c, **k: lances.append(c) or (False, "x", "")):
            compte = installeur.installer_un(outil)
        self.assertFalse(compte["installe"])
        self.assertFalse(any("stratus-red-team@latest" in " ".join(c) for c in lances))
        self.assertIn("no space left", compte["raison"])
        self.assertFalse(compte["raison"].endswith("| "))

    def test_reste_pipx_casse_reinstalle_avec_un_autre_python(self):
        """pipx ignore --python avec --force : il faut désinstaller puis réinstaller."""
        from vigie import installeur
        lances, reinstalle = [], [False]

        def faux_lancer(commande, delai=600):
            lances.append(commande)
            if commande[:2] == ["pipx", "uninstall"]:
                return True, "", "uninstalled garak!"
            if "--python" in commande:
                reinstalle[0] = True
                return True, "", ("installed package garak 0.17.1, installed using Python "
                                  "3.12.3\n  These apps are now available\n    - garak\n")
            return True, "", ("'garak' already seems to be installed. Not modifying "
                              "existing installation in '/opt/vigie-outils/pipx/venvs/garak'.")
        with mock.patch.object(installeur, "_install_documentee",
                               return_value="python -m pip install garak"), \
                mock.patch.object(installeur, "_lancer", side_effect=faux_lancer), \
                mock.patch.object(installeur, "_apps_pipx", return_value=["garak"]), \
                mock.patch.object(installeur, "erreur_demarrage", return_value=""), \
                mock.patch.object(installeur, "repond", side_effect=lambda b: reinstalle[0]):
            compte = installeur._installer_par_doc({"nom": "garak",
                                                    "lien": "https://github.com/NVIDIA/garak"})
        self.assertTrue(compte["repond"], compte)
        self.assertIn("Python 3.12", compte["methode"])
        self.assertEqual(lances[1], ["pipx", "uninstall", "garak"])
        self.assertNotIn("--force", lances[2])
        self.assertIn("--python", lances[2])

    def test_reinstallation_ratee_dit_que_l_outil_n_est_plus_la(self):
        from vigie import installeur

        def faux_lancer(commande, delai=600):
            if "--python" in commande:
                return False, "dépassement de 1800 s", ""
            return True, "", "installed package nebula-ai 2.0.0\n    - nebula\n"
        with mock.patch.object(installeur, "_install_documentee",
                               return_value="pip install nebula-ai"), \
                mock.patch.object(installeur, "_lancer", side_effect=faux_lancer), \
                mock.patch.object(installeur, "erreur_demarrage",
                                  return_value="ImportError: libEGL.so.1"), \
                mock.patch.object(installeur, "repond", return_value=False):
            compte = installeur._installer_par_doc(
                {"nom": "Nebula", "lien": "https://github.com/berylliumsec/nebula"})
        self.assertFalse(compte["installe"])
        self.assertIn("libEGL", compte["raison"])
        self.assertIn("ratée : dépassement", compte["raison"])

    def test_erreur_de_demarrage_jamais_muette(self):
        from vigie import installeur
        with mock.patch.object(installeur.shutil, "which", return_value=None):
            self.assertEqual(installeur.erreur_demarrage(["garak"]),
                             "aucune commande trouvée (garak)")
        with mock.patch.object(installeur.shutil, "which", return_value="/bin/garak"), \
                mock.patch.object(installeur.subprocess, "run",
                                  return_value=subprocess.CompletedProcess([], -9, "", "")):
            self.assertIn("mémoire pleine", installeur.erreur_demarrage(["garak"]))
        with mock.patch.object(installeur.shutil, "which", return_value="/bin/x"), \
                mock.patch.object(installeur.subprocess, "run",
                                  return_value=subprocess.CompletedProcess([], 3, "", "")):
            self.assertIn("code 3", installeur.erreur_demarrage(["x"]))

    def test_appli_a_fenetres_essayee_hors_ecran(self):
        from vigie import installeur
        vus = []
        with mock.patch.object(installeur.shutil, "which", return_value="/bin/nebula"), \
                mock.patch.object(installeur.subprocess, "run",
                                  side_effect=lambda *a, **k: vus.append(k["env"]) or
                                  subprocess.CompletedProcess([], 0, "x" * 50, "")):
            self.assertTrue(installeur.repond("nebula"))
        self.assertEqual(vus[0]["QT_QPA_PLATFORM"], "offscreen")

    def test_nom_pipx_lu_dans_la_reponse(self):
        from vigie import installeur
        self.assertEqual(installeur._venv_pipx(["pipx", "install", "x"],
                                               "'cowsay' (6.1) is already installed. Not"),
                         "cowsay")
        self.assertEqual(installeur._venv_pipx(["pipx", "install", "garak[audio]"], ""),
                         "garak")

    def test_nouvelles_erreurs_expliquees(self):
        from vigie import erreurs
        for raison in ("npm : npm ERR! code ENOTEMPTY",
                       "installé mais ne démarre pas : aucune commande trouvée (garak)",
                       "ImportError: libEGL.so.1: cannot open shared object file"):
            self.assertTrue(erreurs.expliquer_installation(raison), raison)


class RapportDiagComplet(Base):
    """Relecture du diagnostic complet du 26/11/2026 sur pavillon-noir.tech (68/100) :
    incohérences qu'un client remarquerait, faux « correct », faux positifs, outils en panne."""

    def test_dmarc_quarantaine_ne_dit_pas_que_rien_ne_bloque(self):
        from vigie import consequences
        absent = consequences.pour({"cle": "dmarc", "niveau": CRITIQUE,
                                    "titre": "DMARC absent — vu par checkdmarc"})
        quarantaine = consequences.pour({
            "cle": "dmarc", "niveau": INFO,
            "titre": "DMARC en quarantaine, pas encore en blocage — vu par checkdmarc"})
        self.assertIn("Rien ne dit", absent["attaquant"])
        self.assertNotIn("Rien ne dit", quarantaine["attaquant"])
        self.assertIn("indésirable", quarantaine["attaquant"])
        self.assertIn("assurance", quarantaine)      # le reste de la fiche est gardé
        # La fiche commune n'est pas modifiée par la variante.
        self.assertIn("Rien ne dit", consequences.CONSEQUENCES["dmarc"]["attaquant"])

    def test_unlighthouse_sans_duree_fausse_et_sans_recompter_l_accueil(self):
        from vigie.modules import complements
        self.assertNotIn("1 min 30", MODULES["toutes_pages"]["nom"])
        self.assertTrue(complements.est_accueil("https://ex.fr/", "ex.fr"))
        self.assertTrue(complements.est_accueil("https://www.ex.fr", "ex.fr"))
        self.assertFalse(complements.est_accueil("https://ex.fr/article/", "ex.fr"))
        vrai = (complements.pdf.trouver_navigateur, complements.lire_unlighthouse,
                outils.disponible)
        self.addCleanup(lambda: setattr(complements.pdf, "trouver_navigateur", vrai[0])
                        or setattr(complements, "lire_unlighthouse", vrai[1])
                        or setattr(outils, "disponible", vrai[2]))
        complements.pdf.trouver_navigateur = lambda: "/bin/chrome"
        outils.executer = lambda *a, **k: ""
        outils.disponible = lambda nom: True
        complements.lire_unlighthouse = lambda dossier: (30, [
            (5.4, "https://ex.fr/article/"), (4.8, "https://ex.fr/")])
        constats, _ = complements.analyser_pages(CIBLE)
        self.assertIn("1 page lente sur 30", constats[0].titre)
        self.assertNotIn("(4.8 s)", constats[0].explication)
        self.assertIn("mesurée par Lighthouse", constats[0].explication)
        # Seule l'accueil était lente : « correct » pour les autres pages.
        complements.lire_unlighthouse = lambda dossier: (30, [(4.8, "https://ex.fr/")])
        self.assertEqual(complements.analyser_pages(CIBLE)[0][0].niveau, OK)

    def test_sitespeed_meme_cle_que_lighthouse_et_resume_lu(self):
        from vigie.modules import complet
        mesures = complet.lire_resume_sitespeed(
            "INFO: https://ex.fr/ 18 requests, 236 kb, firstPaint: 312ms, Load: 1.23s, "
            "LCP: 4.70s (1 run)")
        self.assertEqual(mesures["fullyLoaded"], 1230)
        self.assertEqual(mesures["largestContentfulPaint"], 4700)
        appels = []

        def faux(nom, arguments, **k):
            appels.append(arguments)
            return resultat("[2026-11-26] INFO: https://ex.fr/ Load: 5.1s, LCP: 4.7s (1 run)\n"
                            "[2026-11-26] INFO: HTML stored in /tmp/x/resultat")
        outils.executer_detail = faux
        constats, _ = complet.analyser_sitespeed(CIBLE)
        self.assertIn("analysisstorer", appels[0])
        self.assertEqual(constats[0].cle, "lenteur")     # fusionné avec Lighthouse
        self.assertIn("4.7 secondes", constats[0].titre)

    def test_sitespeed_sans_mesure_dit_l_erreur(self):
        from vigie.modules import complet
        outils.executer_detail = lambda *a, **k: resultat(
            "[x] ERROR: Could not start Chrome\n[x] INFO: HTML stored in /tmp/x")
        with self.assertRaises(ControleImpossible) as empechement:
            complet.analyser_sitespeed(CIBLE)
        self.assertIn("Could not start Chrome", str(empechement.exception))

    def test_tlsx_cite_comme_source_du_certificat_www(self):
        vrai = outils.disponible
        self.addCleanup(setattr, outils, "disponible", vrai)
        outils.disponible = lambda nom: True
        tlsx = json.dumps({"subject_an": ["ex.fr", "www.ex.fr"]})

        def faux(nom, arguments, **k):
            if nom == "tlsx":
                return tlsx
            return ecrit_fichier("--json_out", LotDix.SSLYZE)(nom, arguments)
        outils.executer = faux
        constats, _ = chiffrement.analyser(CIBLE)
        www = next(c for c in constats if c.cle == "certificat_www")
        self.assertEqual(www.sources, [chiffrement.SOURCE_TLSX])
        self.assertTrue(all(not c.sources for c in constats if c.cle != "certificat_www"))

    def test_metagoofil_en_zero_seconde_n_est_pas_un_correct(self):
        from vigie.modules import complet
        outils.executer_detail = lambda *a, **k: resultat("", "", 0)
        with self.assertRaises(ControleImpossible) as empechement:
            complet.analyser_metagoofil(CIBLE)
        self.assertIn("n'a pas eu lieu", str(empechement.exception))
        # Un plantage : la vraie ligne d'erreur est donnée.
        outils.executer_detail = lambda *a, **k: resultat(
            "", "Traceback (most recent call last):\n  File x\nImportError: googlesearch", 1)
        with self.assertRaises(ControleImpossible) as empechement:
            complet.analyser_metagoofil(CIBLE)
        self.assertIn("ImportError: googlesearch", str(empechement.exception))
        # Une vraie recherche qui ne trouve rien : là, « correct ».
        self.assertEqual(complet.metagoofil_a_cherche(
            resultat("[*] Searching for 40 .pdf files\n"), 0.5), "")
        self.assertEqual(complet.metagoofil_a_cherche(resultat(""), 250), "")

    def test_gau_muet_verifie_par_la_wayback_machine(self):
        outils.executer = lambda *a, **k: ""
        archives.wayback = lambda domaine: ["https://ex.fr/", "https://ex.fr/2026/05/article/"]
        constats, brut = archives.analyser(CIBLE)
        self.assertEqual(brut["archives"]["source"], "wayback")
        self.assertIn("2 pages archivées", constats[0].titre)
        archives._CACHE.clear()
        archives.wayback = lambda domaine: None   # Wayback injoignable : on ne conclut pas
        with self.assertRaises(ControleImpossible):
            archives.analyser(CIBLE)
        archives._CACHE.clear()
        archives.wayback = lambda domaine: []     # les deux d'accord : vraiment rien
        constats, _ = archives.analyser(CIBLE)
        self.assertEqual(constats[0].niveau, OK)
        self.assertIn("Wayback", constats[0].explication)

    def test_myspace_faux_positif_ecarte(self):
        sites = pseudos.recouper({
            "Sherlock": [{"site": "Myspace", "adresse": "a"}, {"site": "YouTube", "adresse": "b"}],
            "Social Analyzer": [{"site": "myspace.com", "adresse": "a"},
                                {"site": "youtube", "adresse": "b"}]})
        self.assertEqual(list(sites), ["youtube"])

    def test_liens_techniques_wordpress_ecartes(self):
        from vigie.modules import liens
        outils.executer = lambda *a, **k: (
            "urlname;parentname;base;result;warningstring;infostring;valid;url\n"
            "https://ex.fr/index.php/wp-json/wp/v2/categories/7;https://ex.fr/c/;;404 Not Found;;;False;x\n"
            "https://ex.fr/index.php/category/ia/feed/;https://ex.fr/c/;;404 Not Found;;;False;x\n"
            "https://ex.fr/wp-content/uploads/2026/10/illu-168-300x158.jpg;https://ex.fr/c/;;"
            "404 Not Found;;;False;x\n"
            "https://ex.fr/contact/;https://ex.fr/;;403 Forbidden;;;False;x\n"
            "https://ex.fr/vieil-article/;https://ex.fr/c/;;404 Not Found;;;False;x\n")
        constats, brut = liens.analyser(CIBLE)
        casse = next(c for c in constats if c.cle == "liens_casses")
        self.assertEqual(casse.titre, "1 lien cassé sur votre site")
        self.assertIn("vieil-article", casse.explication)
        self.assertEqual(brut["ecartes"], 4)

    def test_dnstwist_trop_long_puis_recherche_reduite(self):
        appels = []
        vrai = outils.disponible
        self.addCleanup(setattr, outils, "disponible", vrai)
        outils.disponible = lambda nom: True

        def faux(nom, arguments, delai=0, **k):
            appels.append((list(arguments), delai))
            if "--fuzzers" not in arguments:
                raise ControleImpossible("l'outil dnstwist n'a pas répondu en 240 secondes")
            return resultat(Domaines.SORTIE)
        outils.executer_detail = faux
        constats, brut = domaines.analyser(CIBLE)
        self.assertEqual(len(appels), 2)
        self.assertIn("--fuzzers", appels[1][0])
        self.assertIn("fautes de frappe courantes", brut["note"])
        self.assertIn("fautes de frappe", constats[0].explication)
        # Tout le contrôle tient dans son délai, et le message dit la vraie durée.
        self.assertLess(domaines.DELAI_COMPLET + domaines.DELAI_REDUIT,
                        MODULES["domaines"]["delai"])

        def toujours_trop_long(nom, arguments, delai=0, **k):
            raise ControleImpossible(f"l'outil dnstwist n'a pas répondu en {delai} secondes")
        outils.executer_detail = toujours_trop_long
        with self.assertRaises(ControleImpossible) as empechement:
            domaines.analyser(CIBLE)
        self.assertIn("9 min au total", str(empechement.exception))
        self.assertNotIn("540", str(empechement.exception))

    def test_whatweb_lance_avec_le_correctif_ruby(self):
        from vigie.modules import complet
        vus = {}

        def faux(nom, arguments, env=None, dossier=None, **k):
            vus["env"] = env
            correctif = env["RUBYOPT"].split("-r", 1)[1]
            with open(correctif, encoding="utf-8") as lu:
                vus["correctif"] = lu.read()
            journal = next(a.split("=", 1)[1] for a in arguments if a.startswith("--log-json="))
            with open(journal, "w", encoding="utf-8") as f:
                json.dump([{"plugins": {"WordPress": {"version": ["6.4"]}}}], f)
            return resultat()
        outils.executer_detail = faux
        constats, brut = complet.analyser_whatweb(CIBLE)
        self.assertIn("exists?", vus["correctif"])
        self.assertIn("WordPress 6.4", brut["whatweb"]["technos"])

    def test_trace_ruby_et_python_donnent_la_vraie_erreur(self):
        ruby = ("/usr/share/whatweb/lib/whatweb/x.rb:12:in `load': undefined method "
                "`exists?' for class File (NoMethodError)\n"
                "\tfrom /usr/share/whatweb/lib/y.rb:3:in `go'\n"
                "\tfrom /usr/bin/whatweb:257:in `<main>'")
        raison = outils.pourquoi(resultat("", ruby, 1))
        self.assertIn("Ruby", raison)
        self.assertIn("NoMethodError", raison)
        python = "Traceback (most recent call last):\n  File \"x\", line 1\nKeyError: 'SOA'"
        self.assertIn("KeyError: 'SOA'", outils.pourquoi(resultat("", python, 1)))

    def test_dnsrecon_plante_vigie_lit_la_fiche_et_le_bilan_le_dit(self):
        from vigie import diag_gratuit
        from vigie.modules import complements
        outils.executer_detail = lambda *a, **k: resultat(
            "", "Traceback (most recent call last):\nKeyError: 'SOA'", 1)
        reponses = {("_imaps._tcp.ex.fr", "SRV"): ["0 1 993 ssl0.ovh.net."],
                    ("ex.fr", "AAAA"): ["2001:db8::1"]}
        reseau.dns = lambda nom, typ: reponses.get((nom, typ), [])
        constats, brut = complements.analyser_dns(CIBLE)
        self.assertIn("lecture des mails (IMAP chiffré)", brut["dns_complet"]["services"])
        self.assertNotIn("dnsrecon", constats[0].titre)
        self.assertIn("KeyError", brut["panne"]["dnsrecon"])
        deroule = [{"module": "dns_complet", "nom": "Fiche DNS", "etat": "fini",
                    "detail": "1 point(s) relevé(s)", "duree": 2, "panne": brut["panne"]}]
        ligne = next(l for l in diag_gratuit.bilan(deroule, installe=lambda c: True)
                     if l["outil"] == "dnsrecon")
        self.assertEqual(ligne["etat"], "non_realise")
        self.assertIn("Vigie a lu lui-même", ligne["texte"])


class TestTriOutilsALaMain(unittest.TestCase):
    """Tri du 26/11/2026 des 84 outils « à poser à la main » de la VM Ubuntu."""

    def test_nouvelles_recettes(self):
        from vigie import recettes
        for nom in ("Nuclei Templates", "Maester", "Monkey365", "OWASP ZAP"):
            self.assertIsNotNone(recettes.pour(nom, "linux"), nom)
            self.assertIsNone(recettes.manuel(nom, "linux"), nom)

    def test_chaque_manuel_a_une_raison_et_pas_ici_est_un_manuel(self):
        from vigie import recettes
        self.assertTrue(recettes.PAS_ICI <= set(recettes.MANUELS))
        for nom, (raison, _) in recettes.MANUELS.items():
            self.assertTrue(raison, nom)
        for utile in ("openvas (greenbone community)", "burp suite community", "scubagear"):
            self.assertFalse(recettes.pas_ici(utile))
        self.assertTrue(recettes.pas_ici("Metasploit Framework"))

    def test_bilan_separe_utiles_et_rien_a_faire(self):
        from vigie import installeur
        comptes = [{"nom": "Wazuh", "installe": False, "manuel": True, "raison": "x"},
                   {"nom": "Ghidra", "installe": False, "manuel": True, "raison": "x"},
                   {"nom": "Zeek", "installe": False, "manuel": True, "raison": "x"}]
        bilan = installeur.resume(comptes)
        self.assertEqual((bilan["a_la_main"], bilan["a_poser"], bilan["pas_ici"]), (3, 1, 2))

    def test_sommes_powershell_en_utf16(self):
        from vigie import recettes
        texte = ("a" * 64 + " *powershell-7.7.0-linux-x64.tar.gz\r\n").encode("utf-16")
        with tempfile.TemporaryDirectory() as dossier:
            chemin = os.path.join(dossier, "hashes.sha256")
            with open(chemin, "wb") as f:
                f.write(texte)
            sommes = recettes.lire_sommes(recettes.lire_texte(chemin))
        self.assertEqual(sommes, {"powershell-7.7.0-linux-x64.tar.gz": "a" * 64})

    def test_archive_sans_dossier_de_tete(self):
        import io
        import tarfile
        from vigie import recettes
        with tempfile.TemporaryDirectory() as dossier:
            archive = os.path.join(dossier, "ps.tar.gz")
            with tarfile.open(archive, "w:gz") as tar:
                for nom in ("pwsh", "Modules/a.psd1", "../piege"):
                    info = tarfile.TarInfo(nom)
                    info.size = 2
                    tar.addfile(info, io.BytesIO(b"ok"))
            cible = os.path.join(dossier, "powershell")
            recettes._extraire_tout(archive, cible, retirer_tete=False)
            self.assertTrue(os.path.exists(os.path.join(cible, "pwsh")))
            self.assertTrue(os.path.exists(os.path.join(cible, "Modules", "a.psd1")))
            self.assertFalse(os.path.exists(os.path.join(dossier, "piege")))

    def test_zap_versions_refuse_une_autre_source(self):
        from vigie import recettes
        modele = ("<ZAP><core><linux><url>{}</url><hash>SHA-256:{}</hash></linux>"
                  "</core></ZAP>")
        bonne = "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz"
        self.assertEqual(recettes.lire_zap_versions(modele.format(bonne, "B" * 64)),
                         (bonne, "b" * 64))
        self.assertEqual(recettes.lire_zap_versions(
            modele.format("https://exemple.com/zap.tar.gz", "b" * 64)), (None, None))
        self.assertEqual(recettes.lire_zap_versions("pas du xml"), (None, None))

    def test_module_powershell_ecrit_un_lanceur(self):
        from vigie import recettes
        vrais = (recettes.powershell_a_part, recettes._lancer)
        self.addCleanup(lambda: (setattr(recettes, "powershell_a_part", vrais[0]),
                                 setattr(recettes, "_lancer", vrais[1])))
        appels = []
        recettes.powershell_a_part = lambda: ("/opt/pwsh", "")
        recettes._lancer = lambda commande, **k: appels.append(commande) or (True, "", "")
        with tempfile.TemporaryDirectory() as dossier, \
                mock.patch.dict(os.environ, {"VIGIE_OUTILS_RACINE": dossier,
                                             "PIPX_BIN_DIR": os.path.join(dossier, "bin")}):
            reussi, _, commandes = recettes.pour("Maester", "linux")[1]()
            with open(os.path.join(dossier, "bin", "maester"), encoding="utf-8") as lu:
                lanceur = lu.read()
        self.assertTrue(reussi)
        self.assertEqual(commandes, ["maester"])
        self.assertIn("Install-Module -Name Maester -Repository PSGallery", appels[0][-1])
        self.assertIn("Get-Help Invoke-Maester", lanceur)


class TestSpiderFoot(unittest.TestCase):
    """SpiderFoot piloté par Vigie (spiderfoot.py) : sources choisies, résumé, pannes."""

    CIBLE = "pavillon-noir.tech"

    @staticmethod
    def _json(*evenements):
        """La sortie de SpiderFoot : « [ », un objet par ligne, « ] »."""
        return "[" + ",\n".join(json.dumps({"generated": 1, "type": t, "data": d,
                                            "module": m, "source": src})
                                for t, d, m, src in evenements) + "]\n"

    def _depart(self):
        return [("Internet Name", self.CIBLE, "SpiderFoot UI", self.CIBLE),
                ("Domain Name", self.CIBLE, "SpiderFoot UI", self.CIBLE)]

    def test_fiche_et_ligne(self):
        from vigie import fiches_outils, lancer_seul, spiderfoot
        self.assertTrue(lancer_seul.lancable_ici("SpiderFoot"))
        commande, arguments, verifiee = lancer_seul.ligne_lancement("SpiderFoot", self.CIBLE)
        self.assertEqual(commande, "spiderfoot")
        self.assertTrue(verifiee)
        self.assertEqual(arguments[:2], ["-s", self.CIBLE])
        self.assertEqual(arguments[arguments.index("-m") + 1], ",".join(spiderfoot.MODULES))
        self.assertEqual(arguments[arguments.index("-o") + 1], "json")
        self.assertEqual(arguments[arguments.index("-F") + 1], ",".join(spiderfoot.TYPES))
        self.assertNotIn("-u", arguments)          # jamais « tous les modules d'un usage »
        fiche = fiches_outils.fiche("SpiderFoot")
        self.assertEqual((fiche["cible"], fiche["delai"]), ("domaine", spiderfoot.DELAI))
        # Une adresse de site tapée par erreur redevient le domaine.
        cible, _ = fiches_outils.adapter_cible("SpiderFoot", "https://www.ex.fr/page", fiche)
        self.assertNotIn("/", cible)

    def test_aucune_source_de_fuite_d_attaque_ni_de_personne(self):
        # Les règles d'or : pas de fuites ni de dark web à froid, pas de scan actif, pas
        # de données personnelles. Liste fermée, rien d'écarté n'y revient.
        from vigie import spiderfoot
        self.assertEqual(len(spiderfoot.MODULES), 25)
        self.assertEqual(len(set(spiderfoot.MODULES)), 25)
        ecartes = {m for liste in spiderfoot.ECARTES.values() for m in liste}
        self.assertFalse(set(spiderfoot.MODULES) & ecartes)
        for module in spiderfoot.MODULES:
            self.assertNotRegex(module, r"pwned|dehashed|leak|psbdmp|tor|onion|ahmia|dark|"
                                        r"breach|portscan|brute|zonexfer|nmap|nuclei|email|"
                                        r"names|social|accounts|hunter|phone")
        interdits = {"EMAILADDR", "HUMAN_NAME", "PHONE_NUMBER", "PHYSICAL_ADDRESS",
                     "DOMAIN_WHOIS", "RAW_RIR_DATA", "RAW_DNS_RECORDS", "SSL_CERTIFICATE_RAW",
                     "USERNAME", "ACCOUNT_EXTERNAL_OWNED", "PASSWORD_COMPROMISED"}
        self.assertFalse(set(spiderfoot.TYPES) & interdits)

    def test_lecture_robuste(self):
        # Une bibliothèque écrit au milieu du JSON, et un scan coupé n'a pas de « ] ».
        from vigie import spiderfoot
        sortie = ('[{"generated": 1, "type": "Internet Name", "data": "www.ex.fr", '
                  '"module": "sfp_crt", "source": "ex.fr"}Error trying to connect to '
                  'socket: closing socket\n,\n{"generated": 2, "type": "IP Address", '
                  '"data": "192.0.2.1", "module": "sfp_dnsresolve", "source": "ex.fr"},\n'
                  '{"generated": 3, "type": "Similar Dom')
        trouves = spiderfoot.evenements(sortie)
        self.assertEqual([(e["code"], e["data"]) for e in trouves],
                         [("INTERNET_NAME", "www.ex.fr"), ("IP_ADDRESS", "192.0.2.1")])

    def test_resume_mauvaises_nouvelles_d_abord(self):
        from vigie import spiderfoot
        sortie = self._json(*self._depart(),
                            ("Internet Name", "www." + self.CIBLE, "sfp_crt", self.CIBLE),
                            ("Internet Name", "mail." + self.CIBLE, "sfp_crt", self.CIBLE),
                            ("Internet Name", "blog." + self.CIBLE, "sfp_dnsraw", self.CIBLE),
                            ("IP Address", "192.0.2.10", "sfp_dnsresolve", self.CIBLE),
                            ("Blacklisted IP Address", "Spamhaus (Zen) [192.0.2.10]",
                             "sfp_spamhaus", "192.0.2.10"),
                            ("SSL Certificate Expired", "Nov  1 00:00:00 2026 GMT",
                             "sfp_sslcert", "blog." + self.CIBLE),
                            ("Affiliate - Internet Name Hijackable", "vieux.herokuapp.com",
                             "sfp_subdomain_takeover", "vieux.herokuapp.com"),
                            ("Similar Domain", "pavilon-noir.tech", "sfp_similar",
                             self.CIBLE),
                            ("Hosting Provider", "OVH: https://ovh.com", "sfp_hosting",
                             "192.0.2.10"),
                            ("Email Gateway (DNS 'MX' Records)", "mx1.mail.ovh.net",
                             "sfp_dnsraw", self.CIBLE))
        texte = spiderfoot.resumer(sortie, "", self.CIBLE, 192)
        self.assertIn("(3 min 12 s)", texte)
        self.assertLess(texte.index("À regarder en premier"),
                        texte.index("Ce que SpiderFoot a trouvé"))
        for attendu in ("Listes noires : 1 signalement", "Spamhaus (Zen) [192.0.2.10]",
                        "Certificat HTTPS expiré sur blog." + self.CIBLE,
                        "vieux.herokuapp.com", "3 sous-domaines", "blog, mail, www",
                        "pavilon-noir.tech", "Hébergeur : OVH", "mx1.mail.ovh.net"):
            self.assertIn(attendu, texte)
        self.assertNotIn("Rien d'alarmant", texte)
        self.assertNotIn("incomplet", texte)
        self.assertEqual(spiderfoot.panne(sortie, "", self.CIBLE), "")

    def test_jamais_rien_d_alarmant_sans_recherche(self):
        # Seule la cible de départ revient : aucune source n'a rien dit, on ne rassure pas.
        from vigie import spiderfoot
        texte = spiderfoot.resumer(self._json(*self._depart()), "", self.CIBLE, 20)
        self.assertNotIn("Rien d'alarmant", texte)
        self.assertIn("rien trouvé de public", texte)

    def test_plantage_silencieux_tld(self):
        # SpiderFoot répond « fini » (code 0, « [] ») quand il n'a pas pu télécharger la
        # liste des extensions de domaines : Vigie lit sa trace et le dit en français.
        from vigie import erreurs, spiderfoot
        trace = ("Process Process-1:\nTraceback (most recent call last):\n  File "
                 "\"sfscan.py\", line 206, in __init__\n    raise ValueError(\"Could not "
                 "update TLD list\")\nValueError: Could not update TLD list\n")
        raison = spiderfoot.panne("[]\n", trace, self.CIBLE)
        self.assertIn("publicsuffix.org", raison)
        self.assertIn("Internet", raison)
        self.assertTrue(erreurs.expliquer(trace))
        autre = trace.replace("Could not update TLD list", "boum")
        self.assertIn("ValueError: boum", spiderfoot.panne("[]\n", autre, self.CIBLE))

    def test_sources_injoignables(self):
        from vigie import spiderfoot
        journal = "\n".join(
            f"2026-11-26 12:36:18,685 [ERROR] sflib : Failed to connect to https://{h}/x: "
            "HTTPSConnectionPool(...)" for h in ("crt.sh", "urlscan.io", "api.mnemonic.no",
                                                "www.openphish.com"))
        journal += "\n2026-11-26 12:36:26,447 [INFO] sf : Scan completed with status FINISHED"
        lu = spiderfoot.journal(journal)
        self.assertEqual(lu["statut"], "FINISHED")
        self.assertEqual(len(lu["injoignables"]), 4)
        # Rien trouvé ET 4 sources muettes : c'est une panne, pas un « rien à signaler ».
        self.assertIn("4 sources sans réponse", spiderfoot.panne(
            self._json(*self._depart()), journal, self.CIBLE))
        # Quelque chose trouvé malgré tout : résultat gardé, mais dit incomplet.
        sortie = self._json(*self._depart(),
                            ("Internet Name", "www." + self.CIBLE, "sfp_dnsraw", self.CIBLE))
        self.assertEqual(spiderfoot.panne(sortie, journal, self.CIBLE), "")
        texte = spiderfoot.resumer(sortie, journal, self.CIBLE, 60)
        self.assertIn("résultat incomplet : 4 sources sans réponse", texte)
        self.assertIn("Rien d'alarmant vu par les sources qui ont répondu", texte)

    def test_resolveur_public_regle_une_fois(self):
        import sqlite3
        from vigie import spiderfoot
        with tempfile.TemporaryDirectory() as dossier:
            base = os.path.join(dossier, "spiderfoot.db")
            self.assertFalse(spiderfoot.regler_resolveur("8.8.8.8", base))   # pas de base
            with sqlite3.connect(base) as connexion:
                connexion.execute("CREATE TABLE tbl_config (scope VARCHAR NOT NULL, opt "
                                  "VARCHAR NOT NULL, val VARCHAR NOT NULL, PRIMARY KEY "
                                  "(scope, opt))")
            self.assertTrue(spiderfoot.regler_resolveur("8.8.8.8", base))
            self.assertFalse(spiderfoot.regler_resolveur("9.9.9.9", base))   # choix gardé
            with sqlite3.connect(base) as connexion:
                valeur = connexion.execute("SELECT val FROM tbl_config WHERE scope = "
                                           "'GLOBAL' AND opt = '_dnsserver'").fetchone()
            self.assertEqual(valeur, ("8.8.8.8",))
            remarques = spiderfoot.avant_lancement(None, "1.1.1.1", base)
            self.assertEqual(remarques, [])                       # déjà réglé : silence

    def test_lancement_plante_en_silence_dit_erreur(self):
        from vigie import lancer_seul, spiderfoot
        trace = "Traceback (most recent call last):\nValueError: Could not update TLD list\n"
        vus = {}

        def faux(commande, arguments, delai):
            vus["delai"] = delai
            return {"lance": True, "code": 0, "secondes": 3.5, "sortie": "[]\n",
                    "erreurs": trace, "echoue": False}
        with mock.patch.object(lancer_seul, "_lancer_commande", faux), \
                mock.patch("shutil.which", return_value=None):
            compte = lancer_seul.lancer("SpiderFoot", self.CIBLE, propre_ok=True)
        self.assertEqual(vus["delai"], spiderfoot.DELAI)        # 20 minutes, pas 5
        self.assertTrue(compte["panne"])
        self.assertEqual(compte["explication"][0], "SpiderFoot s'est arrêté en erreur.")
        self.assertIn("publicsuffix.org", compte["explication"][1])

    def test_spiderfoot_reste_actif_hors_diagnostic(self):
        # Famille « audit » : jamais proposé sans autorisation, ni dans le diagnostic.
        from vigie import lancer_seul
        with self.assertRaises(lancer_seul.Refus):
            lancer_seul.verifier_lancable("SpiderFoot")
        self.assertTrue(lancer_seul.info("SpiderFoot")["autorisation_requise"])

    def test_recette_officielle_python_312(self):
        # Le paquet PyPI « spiderfoot-ng » est un fork tiers : retiré, jamais installé.
        from vigie import installeur, recettes, registre
        fiche = next(o for o in registre.charger() if o["nom"] == "SpiderFoot")
        for _, commande in installeur.methodes(fiche):
            self.assertNotIn("spiderfoot-ng", " ".join(commande)
                             if isinstance(commande, (list, tuple)) else str(commande))
        appels, lanceurs = [], {}
        with tempfile.TemporaryDirectory() as dossier, \
                mock.patch.object(recettes, "dossiers",
                                  return_value=(dossier, os.path.join(dossier, "bin"))), \
                mock.patch.object(recettes, "python_a_part",
                                  return_value=("/py312/bin/python3", "")) as python, \
                mock.patch.object(recettes, "_lancer",
                                  side_effect=lambda argv, **_: (appels.append(argv)
                                                                 or (True, "", ""))), \
                mock.patch.object(recettes, "ecrire_lanceur",
                                  side_effect=lambda chemin, lignes: lanceurs.update(
                                      {os.path.basename(chemin): lignes})):
            reussi, _, commandes = recettes.RECETTES["spiderfoot"][1]()
        self.assertTrue(reussi)
        self.assertEqual(commandes, ["spiderfoot"])
        python.assert_called_once_with("3.12")
        self.assertEqual(appels[0], ["pipx", "uninstall", "spiderfoot-ng"])
        self.assertIn("https://github.com/smicallef/spiderfoot", appels[1])
        self.assertEqual(appels[2][:3], ["/py312/bin/python3", "-m", "venv"])
        self.assertTrue(lanceurs["spiderfoot"][-1].endswith('sf.py" "$@"'))

    def test_python_a_part_verifie_l_empreinte(self):
        import hashlib
        import io
        import tarfile
        from vigie import recettes
        with tempfile.TemporaryDirectory() as dossier:
            archive = os.path.join(dossier, "py.tar.gz")
            with tarfile.open(archive, "w:gz") as tar:
                contenu = b"#!/bin/sh\necho 3.12\n"
                membre = tarfile.TarInfo("python/bin/python3")
                membre.size, membre.mode = len(contenu), 0o755
                tar.addfile(membre, io.BytesIO(contenu))
            with open(archive, "rb") as lu:
                bonne = hashlib.sha256(lu.read()).hexdigest()
            nom = "cpython-3.12.16+20261124-x86_64-unknown-linux-gnu-install_only.tar.gz"

            def telecharger(empreinte):
                def faux(url, destination, delai=300):
                    if url == recettes.PBS:
                        contenu = json.dumps({"tag": "20261124",
                                              "asset_url_prefix": "https://x/20261124"})
                    elif url.endswith("SHA256SUMS"):
                        contenu = f"{empreinte}  {nom}\n"
                    else:
                        with open(archive, "rb") as lu, open(destination, "wb") as ecrit:
                            ecrit.write(lu.read())
                        return
                    with open(destination, "w", encoding="utf-8") as ecrit:
                        ecrit.write(contenu)
                return faux
            racine = os.path.join(dossier, "racine")
            with mock.patch.object(recettes, "dossiers", return_value=(racine, dossier)), \
                    mock.patch.object(recettes, "_triplet",
                                      return_value="x86_64-unknown-linux-gnu"):
                with mock.patch.object(recettes, "_telecharger", telecharger("0" * 64)):
                    python, erreur = recettes.python_a_part("3.12")
                self.assertIsNone(python)
                self.assertIn("empreinte", erreur)
                with mock.patch.object(recettes, "_telecharger", telecharger(bonne)):
                    python, erreur = recettes.python_a_part("3.12")
            self.assertEqual(erreur, "")
            self.assertEqual(python, os.path.join(racine, "python3.12", "bin", "python3"))
            self.assertTrue(os.access(python, os.X_OK))


@unittest.skipUnless(sys.platform.startswith("linux"), "groupes de processus Linux")
class TestArretAuTempsMaximum(unittest.TestCase):
    """Un outil trop long est arrêté avec TOUT ce qu'il a lancé, sortie partielle gardée."""

    @staticmethod
    def _vivant(pid):
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as lu:
                return lu.read().rsplit(")", 1)[1].split()[0] != "Z"   # zombie = fini
        except OSError:
            return False

    def _script(self, dossier, corps):
        chemin = os.path.join(dossier, "outil")
        with open(chemin, "w", encoding="utf-8") as ecrit:
            ecrit.write("#!/bin/sh\n" + corps)
        os.chmod(chemin, 0o755)
        return chemin

    def test_fin_normale(self):
        from vigie import lancer_seul
        with tempfile.TemporaryDirectory() as dossier:
            outil = self._script(dossier, "echo trouvé\necho souci >&2\nexit 3\n")
            code, sortie, erreurs, depasse = lancer_seul._executer([outil], 30, dossier)
        self.assertEqual((code, sortie, erreurs, depasse), (3, "trouvé\n", "souci\n", False))

    def test_depassement_arrete_le_groupe_et_garde_le_partiel(self):
        from vigie import lancer_seul
        with tempfile.TemporaryDirectory() as dossier:
            fichier_pid = os.path.join(dossier, "petit-enfant")
            # Comme SpiderFoot : le vrai travail tourne dans un processus à part.
            outil = self._script(dossier, f"sleep 120 &\necho $! > {fichier_pid}\n"
                                          "echo 'premier résultat'\nsleep 120\n")
            debut = time.monotonic()
            code, sortie, _, depasse = lancer_seul._executer([outil], 1, dossier)
            duree = time.monotonic() - debut
            with open(fichier_pid, encoding="utf-8") as lu:
                petit_enfant = int(lu.read())
            for _ in range(50):
                if not self._vivant(petit_enfant):
                    break
                time.sleep(0.1)
        self.assertTrue(depasse)
        self.assertIsNone(code)
        self.assertIn("premier résultat", sortie)
        self.assertLess(duree, 20)
        self.assertFalse(self._vivant(petit_enfant), "le processus lancé par l'outil tourne "
                                                     "encore")

    def test_compte_rendu_partiel(self):
        from vigie import lancer_seul
        compte = {"lance": True, "depasse": True, "delai": 1200, "code": None,
                  "sortie": "www.ex.fr\n", "erreurs": ""}
        phrases = lancer_seul.expliquer("SpiderFoot", compte)
        self.assertIn("20 min", phrases[0])
        self.assertIn("INCOMPLET", phrases[0])
