"""Avancement en direct d'un outil lancé depuis « Lancer un outil »."""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigie import avancement, interface_outils, lancer_seul  # noqa: E402


class TestVraiPourcentage(unittest.TestCase):
    def _suivi(self, texte, flux="erreurs"):
        suivi = avancement.Suivi(delai=300)
        suivi.ajouter(flux, texte.encode())
        return suivi

    def test_pourcentage_ecrit_par_l_outil(self):
        etat = self._suivi("scan\n 45%|████      | 45/100\n").etat()
        self.assertEqual((etat["pourcent"], etat["sorte"]), (45, "outil"))

    def test_barre_effacee_par_retour_chariot(self):
        etat = self._suivi("12%\r37%\r61%").etat()
        self.assertEqual(etat["pourcent"], 61)

    def test_fraction_nuclei(self):
        ligne = "[0:00:05] | Templates: 10 | Matched: 0 | Requests: 50/200 (25%)\n"
        self.assertEqual(self._suivi(ligne).etat()["pourcent"], 25)
        self.assertEqual(self._suivi("Progress: 30 / 120\n").etat()["pourcent"], 25)

    def test_pas_de_faux_pourcentage(self):
        # Un « 150% » ou un pourcentage loin dans la sortie n'est pas un avancement.
        self.assertIsNone(self._suivi("gain 150%\n").etat()["pourcent"])
        vieux = "90%\n" + "mot\n" * 5
        self.assertIsNone(self._suivi(vieux, "sortie").etat()["pourcent"])


class TestEstimation(unittest.TestCase):
    def test_premier_lancement_sans_pourcentage(self):
        etat = avancement.Suivi(delai=300).etat()
        self.assertIsNone(etat["pourcent"])
        self.assertEqual(etat["sorte"], "aucun")
        self.assertEqual(etat["maximum"], "5 min")
        self.assertIn("premier lancement", etat["phrase"])

    def test_estimation_plafonnee(self):
        suivi = avancement.Suivi(delai=300, habituel=10)
        suivi.depart -= 5
        self.assertEqual(suivi.etat()["pourcent"], 50)
        suivi.depart -= 100
        etat = suivi.etat()
        self.assertEqual(etat["pourcent"], avancement.PLAFOND_ESTIMATION)
        self.assertIn("Plus long que d'habitude", etat["phrase"])

    def test_durees_apprises(self):
        with tempfile.TemporaryDirectory() as journal:
            self.assertIsNone(avancement.habituel(journal, "CeWL"))
            for secondes in (100, 200, 120, 0, 9000, 110, 130):
                avancement.noter(journal, "CeWL", secondes)
            with open(os.path.join(journal, avancement.FICHIER_DUREES)) as lu:
                self.assertEqual(len(json.load(lu)["cewl"]), avancement.GARDEES)
            self.assertEqual(avancement.habituel(journal, "cewl"), 130)

    def test_compte_les_lignes(self):
        suivi = avancement.Suivi()
        suivi.ajouter("sortie", "un\ndeux\ntr".encode())
        suivi.ajouter("sortie", "ois\n".encode())
        etat = suivi.etat()
        self.assertEqual(etat["lignes"], 3)
        self.assertIn("3 lignes", etat["activite"])
        self.assertEqual(etat["dernieres"], ["un", "deux", "trois"])


class TestEnDirect(unittest.TestCase):
    def test_executer_donne_la_sortie_pendant_que_ca_tourne(self):
        with tempfile.TemporaryDirectory() as dossier:
            outil = os.path.join(dossier, "outil")
            with open(outil, "w") as ecrit:
                ecrit.write("#!/bin/sh\necho 'premier'\necho '50%' >&2\nsleep 2\necho fin\n")
            os.chmod(outil, 0o755)
            suivi = avancement.Suivi(delai=30)
            import threading
            fini = {}
            fil = threading.Thread(target=lambda: fini.update(
                r=lancer_seul._executer([outil], 30, dossier, suivi=suivi)))
            fil.start()
            time.sleep(1)
            pendant = suivi.etat()
            fil.join()
        self.assertEqual(pendant["pourcent"], 50)
        self.assertEqual(pendant["lignes"], 1)
        self.assertEqual(fini["r"], (0, "premier\nfin\n", "50%\n", False))

    def test_page_et_etat_pendant_le_lancement(self):
        with tempfile.TemporaryDirectory() as journal:
            avancement.noter(journal, "CeWL", 60)
            attendre = __import__("threading").Event()

            def faux_lancer(nom, cible, propre_ok=False, suivi=None):
                suivi.delai = 300
                suivi.ajouter("sortie", b"mot1\nmot2\n")
                attendre.wait(5)
                return {"lance": True, "code": 0, "outil": "CeWL", "secondes": 61,
                        "sortie": "mot1\nmot2\n", "explication": ["ok"],
                        "traduction": "2 mots"}
            with mock.patch.object(interface_outils, "verifier_propre_cible",
                                   return_value=False), \
                    mock.patch.object(lancer_seul, "verifier_lancable"), \
                    mock.patch.object(lancer_seul, "preparer",
                                      return_value={"cible": "https://ex.fr"}), \
                    mock.patch.object(lancer_seul, "lancer", faux_lancer):
                ident = interface_outils.lancer("nom=CeWL&cible=https://ex.fr",
                                                journal=journal)
                time.sleep(0.3)
                etat = interface_outils.etat_avancement(ident)
                page = interface_outils.page_resultat(ident)
                attendre.set()
                for _ in range(50):
                    if not interface_outils.etat_avancement(ident)["en_cours"]:
                        break
                    time.sleep(0.05)
            self.assertTrue(etat["en_cours"])
            self.assertEqual(etat["sorte"], "estimation")
            self.assertEqual(etat["lignes"], 2)
            self.assertIn("id='avancement'", page)
            self.assertIn("estimation", page)
            self.assertIn("/etat", page)
            self.assertFalse(interface_outils.etat_avancement(ident)["en_cours"])
            self.assertNotIn("id='avancement'", interface_outils.page_resultat(ident))
            self.assertEqual(avancement.habituel(journal, "CeWL"), 60.5)


if __name__ == "__main__":
    unittest.main()
