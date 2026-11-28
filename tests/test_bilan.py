"""Bilan d'une cible : ranger chaque lancement, traduire, regrouper sans doublons, rapport."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigie import bilan, interface_bilan  # noqa: E402
from vigie.modeles import CRITIQUE, IMPORTANT, INFO  # noqa: E402

NUCLEI = "\n".join(json.dumps(x) for x in [
    {"template-id": "wp-xmlrpc", "info": {"name": "WordPress xmlrpc", "severity": "medium"},
     "matched-at": "https://www.exemple.fr/xmlrpc.php"},
    {"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info"},
     "matched-at": "https://exemple.fr"}])

NMAP = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="1.2.3.4" addrtype="ipv4"/><hostnames><hostname name="exemple.fr"/></hostnames>
<ports><port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host></nmaprun>"""

ZAP_JSON = json.dumps({"site": [{"@name": "https://exemple.fr", "alerts": [
    {"pluginid": "10038", "alert": "Content Security Policy (CSP) Header Not Set",
     "riskcode": "2", "instances": [{"uri": "https://exemple.fr/"},
                                    {"uri": "https://exemple.fr/a"}]},
    {"pluginid": "99999", "alert": "Something Odd", "riskcode": "1", "instances": []}]}]})

ZAP_XML = """<?xml version="1.0"?><OWASPZAPReport version="2.15"><site name="https://exemple.fr">
<alerts><alertitem><pluginid>10035</pluginid><alert>Strict-Transport-Security Header Not Set</alert>
<riskcode>1</riskcode><instances><instance><uri>https://exemple.fr/</uri></instance></instances>
</alertitem></alerts></site></OWASPZAPReport>"""


class TestRanger(unittest.TestCase):
    def test_enregistrer_et_relire_avec_sous_domaines(self):
        with tempfile.TemporaryDirectory() as d:
            bilan.enregistrer(d, "Subfinder", "https://Exemple.fr/page", "www.exemple.fr\n")
            bilan.enregistrer(d, "httpx", "www.exemple.fr", "https://www.exemple.fr\n")
            bilan.enregistrer(d, "Sherlock", "autre.fr", "x")
            self.assertEqual([c for c, _, _ in bilan.cibles(d)],
                             ["autre.fr", "exemple.fr", "www.exemple.fr"])
            outils = {l["outil"] for l in bilan.lancements(d, "exemple.fr")}
            self.assertEqual(outils, {"Subfinder", "httpx"})

    def test_pas_de_dossier_pas_d_ecriture(self):
        self.assertEqual(bilan.enregistrer(None, "x", "a.fr", "y"), "")

    def test_nom_de_dossier_sur(self):
        self.assertEqual(bilan.cle_cible("../../etc"), "etc")
        self.assertEqual(bilan.cle_cible("Jean@Exemple.fr"), "jean@exemple.fr")


class TestTraduire(unittest.TestCase):
    def test_nuclei(self):
        t = bilan.trouvailles({"outil": "Nuclei", "sortie": NUCLEI}, "exemple.fr")
        failles = [x for x in t if x[0] == "faille"]
        self.assertEqual(failles[0][2], IMPORTANT)
        self.assertIn("www.exemple.fr", [x[1] for x in t if x[0] == "sous-domaine"])

    def test_nmap(self):
        t = bilan.trouvailles({"outil": "nmap", "sortie": NMAP}, "exemple.fr")
        portes = {x[1]: x[2] for x in t if x[0] == "porte"}
        self.assertEqual(set(portes), {"exemple.fr:3389", "exemple.fr:443"})
        self.assertIn(portes["exemple.fr:3389"], (CRITIQUE, IMPORTANT))

    def test_zap_json_et_xml(self):
        t = list(bilan.lire_zap(ZAP_JSON))
        self.assertEqual(t[0][1], "csp")
        self.assertIn("(2 pages)", t[0][3])
        self.assertIn("nom anglais", t[1][3])
        x = list(bilan.lire_zap(ZAP_XML))
        self.assertEqual((x[0][1], x[0][2]), ("hsts", INFO))
        with self.assertRaises(bilan.ImportImpossible):
            list(bilan.lire_zap("bonjour"))

    def test_whatweb(self):
        sortie = ("https://exemple.fr [200 OK] Apache[2.4.58], Country[FRANCE], "
                  "HTTPServer[Ubuntu Linux][Apache/2.4.58], WordPress[6.4], PHP[8.3]")
        technos = {x[1] for x in bilan.trouvailles({"outil": "WhatWeb", "sortie": sortie},
                                                   "exemple.fr") if x[0] == "techno"}
        self.assertTrue({"apache", "wordpress", "php"} <= technos)
        self.assertNotIn("country", technos)

    def test_spiderfoot(self):
        sortie = "[\n" + ",\n".join(json.dumps(x) for x in [
            {"type": "Affiliate - Internet Name - Hijackable", "data": "old.exemple.fr"},
            {"type": "Similar Domain", "data": "exemp1e.fr"},
            {"type": "Internet Name", "data": "mail.exemple.fr"}]) + "\n]"
        t = bilan.trouvailles({"outil": "SpiderFoot", "sortie": sortie}, "exemple.fr")
        genres = {x[0] for x in t}
        self.assertIn("sous-domaine", genres)
        self.assertIn("imitation", genres)


class TestRegrouper(unittest.TestCase):
    def test_recoupement_sans_doublon(self):
        liste = [{"outil": "Subfinder", "sortie": "www.exemple.fr\nmail.exemple.fr"},
                 {"outil": "dnsx", "sortie": "www.exemple.fr [A] [1.2.3.4]"},
                 {"outil": "Nuclei", "sortie": NUCLEI, "garde": "propre cible"}]
        r = bilan.regrouper(liste, "exemple.fr")
        www = [t for t in r["genres"]["sous-domaine"] if t["cle"] == "www.exemple.fr"][0]
        self.assertEqual(www["outils"], ["Subfinder", "dnsx", "Nuclei"])
        self.assertEqual(len(r["genres"]["sous-domaine"]), 2)
        self.assertEqual(r["actifs"], ["propre cible"])
        self.assertTrue(any("à corriger" in p for p in r["phrases"]))

    def test_rapport(self):
        liste = [{"outil": "nmap", "sortie": NMAP, "garde": "propre cible"},
                 {"outil": "ZAP", "sortie": ZAP_JSON},
                 {"outil": "Subfinder", "sortie": "www.exemple.fr"}]
        r = bilan.regrouper(liste, "exemple.fr")
        constats = bilan.constats(r)
        cles = {c.cle for c in constats}
        self.assertIn("csp", cles)                      # relié aux Conséquences
        self.assertIn("sous_domaines", cles)
        with tempfile.TemporaryDirectory() as d:
            nom = bilan.faire_rapport(r, "exemple.fr", d)
            self.assertRegex(nom, r"^[a-z0-9_-]{3,120}$")
            with open(os.path.join(d, nom, "rapport.json"), encoding="utf-8") as f:
                rapport = json.load(f)
            self.assertIn("propre cible", json.dumps(rapport["autorisation"]))
            self.assertTrue(os.path.exists(os.path.join(d, nom, "rapport-executif.html")))


class TestInterface(unittest.TestCase):
    def test_pages_et_import(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("Aucun résultat", interface_bilan.page(d))
            corps = "cible=exemple.fr&contenu=" + __import__("urllib.parse").parse.quote(ZAP_JSON)
            cible, phrase = interface_bilan.importer(d, corps)
            self.assertIn("2 alertes", phrase)
            bilan.enregistrer(d, "Subfinder", "exemple.fr", "www.exemple.fr")
            page = interface_bilan.page_cible(d, cible)
            self.assertIn("Points relevés", page)
            self.assertIn("Aucune politique de contenu", page)
            # Décocher ZAP : ses alertes disparaissent du bilan.
            ids = [l["id"] for l in bilan.lancements(d, "exemple.fr") if l["outil"] != "ZAP"]
            page = interface_bilan.page_cible(d, cible, set(ids))
            self.assertNotIn("Aucune politique de contenu", page)
            with tempfile.TemporaryDirectory() as sortie:
                nom = interface_bilan.faire_rapport(
                    d, "cible=exemple.fr&choix=1&garder=" + ids[0], sortie)
                self.assertTrue(os.path.isdir(os.path.join(sortie, nom)))


if __name__ == "__main__":
    unittest.main()
