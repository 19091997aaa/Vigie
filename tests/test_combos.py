"""Onglet « Combos » : plusieurs outils enchaînés sur une cible, garde-fous et regroupement."""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigie import combos, interface_combos, lancer_seul  # noqa: E402


class TestDefinitions(unittest.TestCase):
    def test_outils_existent_et_se_lancent(self):
        for combo in combos.COMBOS:
            self.assertFalse(combos.resume_combos()[combos.COMBOS.index(combo)]["manquants"])
            for nom, _ in combo["etapes"]:
                self.assertTrue(lancer_seul.lancable_ici(nom), nom)

    def test_aucun_outil_offensif(self):
        for combo in combos.COMBOS:
            for nom, _ in combo["etapes"]:
                self.assertNotEqual(lancer_seul.info(nom)["famille"], "gate", nom)

    def test_combo_actif_seulement_outils_qui_demandent_autorisation_ou_passifs(self):
        # Un combo « passif » ne contient aucun outil actif sauf SpiderFoot (sauté si
        # la cible n'est pas à soi).
        for combo in combos.COMBOS:
            if combo["genre"] == "passif":
                actifs = {n for n, _ in combo["etapes"]
                          if lancer_seul.info(n)["autorisation_requise"]}
                self.assertLessEqual(actifs, {"SpiderFoot"}, combo["id"])


class TestGardeFous(unittest.TestCase):
    def test_personne_sans_accord_refuse(self):
        with self.assertRaises(combos.Refus):
            combos.preparer("pseudos", "jean.dupont")
        plan = combos.preparer("pseudos", "@jean.dupont", accord=True)
        self.assertEqual(plan["cible"], "jean.dupont")

    def test_email_donne_le_domaine_a_theharvester(self):
        plan = combos.preparer("email", "Contact@Exemple.fr", accord=True)
        cibles = {e["outil"]: e["cible"] for e in plan["etapes"]}
        self.assertEqual(cibles["theHarvester"], "exemple.fr")
        self.assertEqual(cibles["Holehe"], "contact@exemple.fr")

    def test_actif_refuse_hors_de_mes_cibles(self):
        def pas_a_moi(nom, cible):
            if lancer_seul.info(nom)["autorisation_requise"]:
                raise lancer_seul.Refus("pas une de tes cibles")
            return False
        with self.assertRaises(combos.Refus):
            combos.preparer("failles", "exemple.fr", propre=pas_a_moi)

    def test_passif_saute_spiderfoot_hors_de_mes_cibles(self):
        plan = combos.preparer("domaine", "https://exemple.fr/page")
        self.assertEqual(plan["cible"], "exemple.fr")
        sautes = [e["outil"] for e in plan["etapes"] if e["saute"]]
        self.assertEqual(sautes, ["SpiderFoot"])

    def test_actif_sur_mes_cibles(self):
        plan = combos.preparer("failles", "exemple.fr",
                               propre=lambda n, c: lancer_seul.info(n)["autorisation_requise"])
        self.assertFalse(any(e["saute"] for e in plan["etapes"]))
        nikto = [e for e in plan["etapes"] if e["outil"] == "Nikto"][0]
        self.assertEqual(nikto["cible"], "https://exemple.fr")

    def test_mauvaise_cible(self):
        with self.assertRaises(combos.Refus):
            combos.preparer("email", "pas-une-adresse", accord=True)
        with self.assertRaises(combos.Refus):
            combos.preparer("inconnu", "exemple.fr")


class TestRegroupement(unittest.TestCase):
    def test_sous_domaines_sans_doublon_avec_qui_a_vu(self):
        res = [{"outil": "Subfinder", "reussi": True, "lance_par_vigie": True,
                "sortie": "www.exemple.fr\nmail.exemple.fr\n"},
               {"outil": "dnsx", "reussi": True, "lance_par_vigie": True,
                "sortie": "\x1b[32mwww.exemple.fr\x1b[0m [A] [1.2.3.4]\nautre.fr\n"},
               {"outil": "SpiderFoot", "saute": True}]
        r = combos.regrouper(combos.PAR_ID["domaine"], "exemple.fr", res)
        bloc = r["blocs"][0]
        self.assertEqual(bloc["lignes"][0], ("www.exemple.fr", ["Subfinder", "dnsx"]))
        self.assertIn(("mail.exemple.fr", ["Subfinder"]), bloc["lignes"])
        self.assertNotIn("autre.fr", [c for c, _ in bloc["lignes"]])
        self.assertTrue(any("recoupés" in p for p in r["bilan"]))
        self.assertTrue(any("SpiderFoot" in p for p in r["bilan"]))

    def test_profils_un_par_site(self):
        res = [{"outil": "Sherlock", "reussi": True, "lance_par_vigie": True,
                "sortie": "[+] GitHub: https://github.com/jean\n[-] Foo: Not Found!\n"},
               {"outil": "Maigret", "reussi": True, "lance_par_vigie": True,
                "sortie": "[+] GitHub: https://www.github.com/jean/\n"
                          "[+] Reddit: https://reddit.com/user/jean\n"}]
        r = combos.regrouper(combos.PAR_ID["pseudos"], "jean", res)
        lignes = dict(r["blocs"][0]["lignes"])
        self.assertEqual(len(lignes), 2)
        self.assertEqual(lignes["github.com : https://github.com/jean"],
                         ["Maigret", "Sherlock"])


class TestInterface(unittest.TestCase):
    def test_page(self):
        with mock.patch.object(interface_combos.presence, "etat", return_value={}):
            page = interface_combos.page()
        for combo in combos.COMBOS:
            self.assertIn(combo["titre"].replace("'", "&#x27;"), page)
        self.assertIn("accord", page)

    def test_lancement_enchaine_et_regroupe(self):
        sorties = {"Subfinder": "www.exemple.fr\n", "dnsx": "www.exemple.fr\nftp.exemple.fr\n"}
        lances = []

        def faux(nom, cible, propre_ok=False, suivi=None):
            lances.append(nom)
            return {"lance": True, "code": 0, "sortie": sorties.get(nom, ""),
                    "outil": nom, "explication": ["ok"], "traduction": "résumé",
                    "commande": nom}
        with tempfile.TemporaryDirectory() as journal, \
                mock.patch.object(lancer_seul, "lancer", side_effect=faux):
            ident = interface_combos.lancer("combo=domaine&cible=exemple.fr", None, journal)
            for _ in range(100):
                if interface_combos.LANCEMENTS[ident]["etat"] == "fini":
                    break
                time.sleep(0.05)
            page = interface_combos.page_resultat(ident)
        self.assertEqual(lances, ["Subfinder", "dnsx"])          # SpiderFoot sauté
        self.assertIn("Bilan commun", page)
        self.assertIn("ftp.exemple.fr", page)
        self.assertIn("Sauté", page)


if __name__ == "__main__":
    unittest.main()
