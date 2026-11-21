"""Essais sans internet : on remplace le réseau par des réponses préparées.

    python3 -m unittest discover -s tests
"""
import json
import os
import ssl
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


class Base(unittest.TestCase):
    def setUp(self):
        self._sauve = (reseau.dns, site._ouvrir, site._jours_certificat, outils.executer,
                       metadonnees._ouvrir)
        # Aucun essai ne télécharge pour de vrai, et aucun résultat d'un essai ne
        # resserre dans le suivant (les modules gardent 10 minutes ce qu'ils ont trouvé).
        metadonnees._ouvrir = pas_de_telechargement
        sousdomaines._CACHE.clear()
        archives._CACHE.clear()

    def tearDown(self):
        (reseau.dns, site._ouvrir, site._jours_certificat, outils.executer,
         metadonnees._ouvrir) = self._sauve

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

    def test_resolveurs_publics_et_domaine_en_dernier(self):
        # Essai réel du 21/11/2026 : par la box, plus de 10 minutes ; en public, 13 secondes.
        args = domaines.arguments("ex.fr")
        self.assertEqual(args[-1], "ex.fr")
        self.assertEqual(args[args.index("--nameservers") + 1], ",".join(reseau.SERVEURS_DNS))

    def test_sortie_vide_dit_comment_reparer(self):
        # Cas réel : dnstwist installé sans son module DNS ne renvoie rien.
        outils.executer = lambda *a, **k: ""
        with self.assertRaises(ControleImpossible) as empechement:
            domaines.analyser(CIBLE)
        self.assertIn("dnstwist[full]", str(empechement.exception))


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
        with tempfile.TemporaryDirectory() as sortie:
            base = self.demarrer(sortie)
            accueil = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("Nouveau diagnostic", accueil)
            reponse = urllib.request.urlopen(base + "/diagnostic",
                                             data=b"domaine=ex.fr&societe=Essai")
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
                mock.patch.dict(interface.MODULES, modules):
            ident = interface.nouveau_suivi(Cible("ex.fr"), ["a", "b"])
            interface.executer_suivi(ident, Cible("ex.fr"), ["a", "b"], "inutile")
        etat = interface.etat_suivi(ident)
        self.assertEqual(etat["etat"], "erreur")
        self.assertEqual([e["etat"] for e in etat["etapes"]], ["non_realise", "echec"])
        self.assertEqual(etat["etapes"][0]["detail"], "pas de réseau")
        self.assertIn("outil introuvable", etat["erreur"])

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
                         ["brew (documenté)", "pipx (documenté)", "pipx (dépôt)", "go (dépôt)"])
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
        self.assertEqual(len(installeur.methodes(outil, install="pip3 install -r req.txt")), 2)

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
        self.assertTrue(any(c.niveau == IMPORTANT and "test.ex.fr" in c.titre for c in constats))

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
