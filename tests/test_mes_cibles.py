"""« Mes propres cibles » (mes_cibles.py) et leur usage dans les outils manuels."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigie import interface_manuel, manuel, mes_cibles, reseau  # noqa: E402


class FauxDNS:
    """Un DNS public imité : {(nom, type): [valeurs]}."""

    def __init__(self, zones):
        self.zones = zones

    def __call__(self, nom, typ):
        return list(self.zones.get((nom, typ), []))


def _dns_prouve(jeton, plus=None):
    zones = {("mon-site.fr", "TXT"): ["v=spf1 -all", jeton],
             ("mon-site.fr", "A"): ["203.0.113.10"]}
    zones.update(plus or {})
    return FauxDNS(zones)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dossier = os.path.join(self._tmp.name, "autorisations")
        self.journal = os.path.join(self._tmp.name, "journal")

    def tearDown(self):
        self._tmp.cleanup()

    def prouver(self, plus=None):
        _, jeton = mes_cibles.ajouter_domaine(self.dossier, self.journal, "https://www.Mon-Site.fr/")
        dns = _dns_prouve(jeton, plus)
        mes_cibles.prouver_domaine(self.dossier, self.journal, "mon-site.fr", resoudre=dns)
        return dns


class Domaines(Base):
    def test_domaine_atteste_compte_sans_preuve(self):
        # L'attestation suffit : le domaine lui-même passe sans code DNS.
        mes_cibles.ajouter_domaine(self.dossier, self.journal, "mon-site.fr")
        self.assertIsNone(mes_cibles.raison_refus(self.dossier, "mon-site.fr", FauxDNS({})))

    def test_preuve_dns_facultative_reste_possible(self):
        _, jeton = mes_cibles.ajouter_domaine(self.dossier, self.journal, "mon-site.fr")
        with self.assertRaises(mes_cibles.Refus):   # code pas encore posé
            mes_cibles.prouver_domaine(self.dossier, self.journal, "mon-site.fr",
                                       resoudre=FauxDNS({}))
        dns = FauxDNS({("mon-site.fr", "TXT"): [jeton]})
        self.assertTrue(mes_cibles.prouver_domaine(self.dossier, self.journal,
                                                   "mon-site.fr", resoudre=dns))

    def test_domaine_prouve_couvert(self):
        dns = self.prouver()
        self.assertIsNone(mes_cibles.raison_refus(self.dossier, "mon-site.fr", dns))

    def test_code_retire_ne_compte_plus(self):
        self.prouver()
        sans_code = FauxDNS({("mon-site.fr", "A"): ["203.0.113.10"]})
        self.assertIn("plus dans le DNS",
                      mes_cibles.raison_refus(self.dossier, "mon-site.fr", sans_code))

    def test_autre_domaine_refuse(self):
        dns = self.prouver()
        self.assertIn("autorisation signée", mes_cibles.raison_refus(self.dossier, "autre.fr", dns))
        # Un nom qui finit pareil sans être un sous-domaine ne passe pas.
        self.assertIsNotNone(mes_cibles.raison_refus(self.dossier, "faux-mon-site.fr", dns))

    def test_sous_domaine_meme_machine(self):
        dns = self.prouver({("www.mon-site.fr", "A"): ["203.0.113.10"]})
        self.assertIsNone(mes_cibles.raison_refus(self.dossier, "www.mon-site.fr", dns))

    def test_sous_domaine_autre_machine_refuse(self):
        dns = self.prouver({("boutique.mon-site.fr", "A"): ["198.51.100.7"]})
        raison = mes_cibles.raison_refus(self.dossier, "boutique.mon-site.fr", dns)
        self.assertIn("autre machine", raison)

    def test_sous_domaine_cname_exterieur_refuse(self):
        dns = self.prouver({("shop.mon-site.fr", "CNAME"): ["shops.hebergeur.com."],
                              ("shop.mon-site.fr", "A"): ["203.0.113.10"]})
        raison = mes_cibles.raison_refus(self.dossier, "shop.mon-site.fr", dns)
        self.assertIn("shops.hebergeur.com", raison)

    def test_sous_domaine_dns_injoignable_refuse(self):
        self.prouver()

        def panne(nom, typ):
            raise reseau.ErreurReseau("pas d'internet")
        # Le domaine lui-même passe (déjà attesté) ; un sous-domaine non vérifiable, non.
        self.assertIsNone(mes_cibles.raison_refus(self.dossier, "mon-site.fr", panne))
        self.assertIn("impossible de vérifier",
                      mes_cibles.raison_refus(self.dossier, "www.mon-site.fr", panne))

    def test_journal(self):
        self.prouver()
        with open(os.path.join(self.journal, "mes-cibles.jsonl"), encoding="utf-8") as f:
            actions = [json.loads(l)["action"] for l in f]
        self.assertEqual(actions, ["domaine déclaré (attestation de propriété)",
                                   "domaine prouvé (code DNS lu)"])


class Labo(Base):
    def test_reseau_prive(self):
        mes_cibles.ajouter_reseau(self.dossier, self.journal, "192.168.56.0/24")
        self.assertIsNone(mes_cibles.raison_refus(self.dossier, "192.168.56.12", FauxDNS({})))
        self.assertIsNotNone(mes_cibles.raison_refus(self.dossier, "192.168.57.12", FauxDNS({})))

    def test_reseau_public_refuse(self):
        for texte in ("8.8.8.8", "203.0.113.0/24", "0.0.0.0/0", "100.64.0.0/10", "8.0.0.0/7", "pas-une-ip"):
            with self.assertRaises(mes_cibles.Refus):
                mes_cibles.ajouter_reseau(self.dossier, self.journal, texte)

    def test_ip_publique_jamais_couverte(self):
        self.prouver()
        self.assertIn("autorisation signée",
                      mes_cibles.raison_refus(self.dossier, "203.0.113.10", FauxDNS({})))


class OutilsManuels(Base):
    def test_lancement_sans_fiche_sur_ma_cible(self):
        mes_cibles.ajouter_reseau(self.dossier, self.journal, "192.168.56.0/24")
        with mock.patch.object(manuel.outils, "executer", return_value="<nmaprun/>"):
            chemin = manuel.lancer("nmap", "192.168.56.12", None, None, "192.168.56.12",
                                   journal=self.journal, dossier_cibles=self.dossier)
        self.assertTrue(os.path.isfile(chemin))
        with open(os.path.join(self.journal, "lancements.jsonl"), encoding="utf-8") as f:
            ligne = json.loads(f.readline())
        self.assertIn("propre cible", ligne["autorisation"])

    def test_sans_fiche_ailleurs_refuse(self):
        with mock.patch.object(manuel.outils, "executer") as executer:
            with self.assertRaises(manuel.Refus):
                manuel.lancer("nmap", "8.8.8.8", None, None, "8.8.8.8",
                              journal=self.journal, dossier_cibles=self.dossier)
        executer.assert_not_called()

    def test_sans_dossier_de_cibles_fiche_obligatoire(self):
        with self.assertRaises(manuel.Refus):
            manuel.lancer("nmap", "192.168.56.12", None, None, "192.168.56.12",
                          journal=self.journal)

    def test_confirmation_toujours_exigee(self):
        mes_cibles.ajouter_reseau(self.dossier, self.journal, "192.168.56.0/24")
        with self.assertRaises(manuel.Refus):
            manuel.lancer("nmap", "192.168.56.12", None, None, "",
                          journal=self.journal, dossier_cibles=self.dossier)


class Interface(Base):
    def test_page_et_formulaires(self):
        p = interface_manuel.page(self.dossier)
        self.assertIn("Mes propres cibles", p)
        self.assertIn("Aucune : c'est une de mes propres cibles", p)
        texte = interface_manuel.gerer_cibles("action=domaine&valeur=mon-site.fr&atteste=oui",
                                              self.dossier, self.journal)
        self.assertIn("vigie-verification=", texte)
        self.assertIn("attestation de propriété", interface_manuel.page(self.dossier))

    def test_attestation_obligatoire(self):
        with self.assertRaises(mes_cibles.Refus):
            interface_manuel.gerer_cibles("action=reseau&valeur=192.168.1.0/24",
                                          self.dossier, self.journal)

    def test_lancer_sans_fiche_hors_cibles_refuse(self):
        with self.assertRaises(manuel.Refus):
            interface_manuel.lancer("outil=nmap&cible=exemple.fr&fiche=&signee="
                                    "&confirmation=exemple.fr", self.dossier, self.journal)


class LancerUnOutil(Base):
    """Onglet « Lancer un outil » : actifs/offensifs seulement sur mes cibles prouvées."""

    def test_offensif_hors_cibles_refuse(self):
        from vigie import interface_outils, lancer_seul
        with self.assertRaises(lancer_seul.Refus) as refus:
            interface_outils.lancer("nom=sqlmap&cible=https://autre.fr/?id=1",
                                    self.dossier, self.journal)
        self.assertIn("autorisation signée", str(refus.exception))

    def test_offensif_sans_dossier_refuse(self):
        from vigie import interface_outils, lancer_seul
        with self.assertRaises(lancer_seul.Refus):
            interface_outils.lancer("nom=sqlmap&cible=192.168.56.12")

    def test_offensif_sur_mon_labo_part(self):
        from vigie import interface_outils, lancer_seul
        mes_cibles.ajouter_reseau(self.dossier, self.journal, "192.168.56.0/24")
        self.assertTrue(interface_outils.verifier_propre_cible(
            "sqlmap", "http://192.168.56.12/page?id=1", self.dossier))
        # Le garde-fou « passif seulement » est levé uniquement dans ce cas.
        lancer_seul.verifier_lancable("sqlmap", autorisation_ok=True)

    def test_passif_inchange(self):
        from vigie import interface_outils
        self.assertFalse(interface_outils.verifier_propre_cible("Sherlock", "x", None))

    def test_hote(self):
        from vigie import lancer_seul
        self.assertEqual(lancer_seul.hote("https://Mon-Site.fr:8443/a"), "mon-site.fr")
        self.assertEqual(lancer_seul.hote("mon-site.fr/x"), "mon-site.fr")
        self.assertEqual(lancer_seul.hote("192.168.56.12:80"), "192.168.56.12")


if __name__ == "__main__":
    unittest.main()
