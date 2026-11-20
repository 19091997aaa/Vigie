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

from vigie import (autorisation, cli, comparaison, interface, outils,  # noqa: E402
                   rapport, reseau, scenarios)
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


if __name__ == "__main__":
    unittest.main()
