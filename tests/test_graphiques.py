"""Onglet « Ouvrir un outil » (graphiques.py, interface_graphiques.py)."""
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigie import graphiques, interface_graphiques, registre  # noqa: E402
from vigie.graphiques import _cmd, _web, _appli  # noqa: E402


def _port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Muet(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def _script(dossier, contenu):
    chemin = os.path.join(dossier, "faux-outil")
    with open(chemin, "w") as f:
        f.write("#!/bin/sh\n" + contenu + "\n")
    os.chmod(chemin, os.stat(chemin).st_mode | stat.S_IEXEC)
    return chemin


class Catalogue(unittest.TestCase):
    def test_noms_du_registre_et_genres(self):
        noms = {o["nom"] for o in registre.charger()}
        for nom, fiche in graphiques.INTERFACES.items():
            self.assertIn(nom, noms)
            self.assertIn(fiche["genre"], graphiques.GENRES)
            if fiche["genre"] == "web":
                self.assertTrue(fiche["url"].startswith(("http://127.0.0.1", "https://127.0.0.1")))
                self.assertTrue(fiche["demarrer"])

    def test_outils_demandes_presents(self):
        for nom in ("Ghidra", "Burp Suite Community", "Autopsy", "CyberChef", "SpiderFoot",
                    "Wazuh", "OpenVAS (Greenbone Community)", "Uptime Kuma", "Shannon"):
            self.assertIn(nom, graphiques.INTERFACES)

    def test_engagement_pour_audit_et_offensif(self):
        self.assertTrue(graphiques.demande_engagement("Shannon"))           # gate
        self.assertTrue(graphiques.demande_engagement("Burp Suite Community"))  # audit
        self.assertFalse(graphiques.demande_engagement("Ghidra"))           # secu


class Verifier(unittest.TestCase):
    def test_inconnu_refuse(self):
        with self.assertRaises(graphiques.Refus):
            graphiques.verifier("nmap")

    def test_offensif_sans_case_refuse(self):
        with self.assertRaises(graphiques.Refus) as refus:
            graphiques.verifier("Shannon", engagement=False)
        self.assertIn("autorisation signée", str(refus.exception))
        from vigie import cles_ia     # case cochée + clé d'IA enregistrée : accepté
        with mock.patch.object(cles_ia, "lire", return_value={"fournisseur": "openai"}):
            graphiques.verifier("Shannon", engagement=True)


class OuvrirWeb(unittest.TestCase):
    def test_service_deja_en_marche(self):
        port = _port_libre()
        serveur = ThreadingHTTPServer(("127.0.0.1", port), _Muet)
        threading.Thread(target=serveur.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{port}"
            with mock.patch.dict(graphiques.INTERFACES, {"Web-Check": _web(url, _cmd("absent"))}):
                self.assertEqual(graphiques.etat("Web-Check")["en_marche"], True)
                fin = graphiques.ouvrir("Web-Check")
            self.assertEqual(fin["url"], url)
        finally:
            serveur.shutdown()
            serveur.server_close()

    def test_demarre_puis_ouvre_et_donne_le_mot_de_passe(self):
        port = _port_libre()
        with tempfile.TemporaryDirectory() as d:
            script = _script(d, "echo 'Please login with the username admin and the "
                                "password a1b2c3d4e5'\n"
                                f"exec {sys.executable} -m http.server {port} --bind 127.0.0.1")
            url = f"http://127.0.0.1:{port}"
            fiche = _web(url, _cmd(script), attente=20)
            with mock.patch.dict(graphiques.INTERFACES, {"Gophish": fiche}), \
                    mock.patch.object(graphiques, "_dossier_vigie", return_value=d):
                fin = graphiques.ouvrir("Gophish")
                processus_url = fin["url"]
            self.assertEqual(processus_url, url)
            self.assertIn("a1b2c3d4e5", fin["message"])
            self.assertTrue(fin["garder"])
            os.system(f"pkill -f 'http.server {port}' >/dev/null 2>&1")

    def test_rien_pour_demarrer(self):
        fiche = _web(f"http://127.0.0.1:{_port_libre()}", _cmd("commande-qui-n-existe-pas"))
        with mock.patch.dict(graphiques.INTERFACES, {"Web-Check": fiche}):
            self.assertFalse(graphiques.etat("Web-Check")["present"])
            with self.assertRaises(graphiques.Refus) as refus:
                graphiques.ouvrir("Web-Check")
        self.assertIn("pas installé", str(refus.exception))


class OuvrirAppli(unittest.TestCase):
    def test_sans_ecran(self):
        with tempfile.TemporaryDirectory() as d:
            script = _script(d, "sleep 1")
            env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
            with mock.patch.dict(graphiques.INTERFACES, {"Ghidra": _appli([script])}), \
                    mock.patch.object(graphiques, "systeme", return_value="Linux"), \
                    mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(graphiques.Refus) as refus:
                    graphiques.ouvrir("Ghidra")
        self.assertIn("sans écran", str(refus.exception))

    def test_plantage_explique(self):
        with tempfile.TemporaryDirectory() as d:
            script = _script(d, "echo 'cannot open display' >&2; exit 1")
            with mock.patch.dict(graphiques.INTERFACES, {"Ghidra": _appli([script])}), \
                    mock.patch.object(graphiques, "systeme", return_value="Linux"), \
                    mock.patch.object(graphiques, "_dossier_vigie", return_value=d), \
                    mock.patch.dict(os.environ, {"DISPLAY": ":0"}):
                with self.assertRaises(graphiques.Refus) as refus:
                    graphiques.ouvrir("Ghidra")
        self.assertIn("s'est arrêté tout de suite", str(refus.exception))

    def test_fenetre_ouverte(self):
        with tempfile.TemporaryDirectory() as d:
            script = _script(d, "sleep 6")
            with mock.patch.dict(graphiques.INTERFACES, {"Ghidra": _appli([script])}), \
                    mock.patch.object(graphiques, "systeme", return_value="Linux"), \
                    mock.patch.object(graphiques, "_dossier_vigie", return_value=d), \
                    mock.patch.dict(os.environ, {"DISPLAY": ":0"}):
                fin = graphiques.ouvrir("Ghidra")
        self.assertIn("propre fenêtre", fin["message"])


class ALaMain(unittest.TestCase):
    def test_commande_connue_de_vigie(self):
        # Un outil branché « à la main » sous le nom que Vigie connaît s'ouvre aussi.
        with tempfile.TemporaryDirectory() as d:
            script = _script(d, "sleep 1")
            with mock.patch.object(graphiques, "_binaires_connus", return_value=[script]), \
                    mock.patch.dict(graphiques.INTERFACES,
                                    {"Ghidra": _appli(["commande-absente"])}):
                self.assertEqual(graphiques.commande_dispo("Ghidra"), [script])
                self.assertTrue(graphiques.etat("Ghidra")["present"])

    def test_lanceur_a_la_main_pour_un_service_web(self):
        from vigie import a_la_main
        with tempfile.TemporaryDirectory() as d:
            lanceur = _script(d, a_la_main.MARQUE + "\nexit 0")
            fiche = _web("http://127.0.0.1:1", _cmd("commande-absente"))
            with mock.patch.object(graphiques, "_binaires_connus", return_value=[lanceur]), \
                    mock.patch.dict(graphiques.INTERFACES, {"Velociraptor": fiche}):
                self.assertEqual(graphiques.lanceur_a_la_main("Velociraptor"), lanceur)
                self.assertTrue(graphiques.etat("Velociraptor")["present"])


class Journal(unittest.TestCase):
    def test_ouverture_offensive_notee(self):
        with tempfile.TemporaryDirectory() as d:
            fiche = {"genre": "lien", "url": "https://exemple.org", "note": ""}
            with mock.patch.dict(graphiques.INTERFACES, {"Shannon": fiche}):
                graphiques.ouvrir("Shannon", engagement=True, journal=d)
            with open(os.path.join(d, "ouvertures.jsonl"), encoding="utf-8") as f:
                ligne = json.loads(f.readline())
        self.assertEqual(ligne["outil"], "Shannon")
        self.assertEqual(ligne["famille"], "gate")


class Page(unittest.TestCase):
    def test_page_separe_prets_et_absents(self):
        def faux_etat(nom):
            return {"present": nom in ("Ghidra", "Shannon"), "en_marche": None}
        with mock.patch.object(graphiques, "etat", side_effect=faux_etat):
            p = interface_graphiques.page()
        self.assertIn("Prêts à ouvrir (2)", p)
        prets, absents = p.split("Pas encore sur cette machine")
        self.assertIn("Ghidra", prets)
        self.assertIn("name='engagement'", prets)          # Shannon : case obligatoire
        self.assertNotIn("Velociraptor", prets)
        self.assertIn("Velociraptor", absents)
        self.assertNotIn("<button", absents)              # aucun bouton qui promet
        # Le bloc « Je l'ai installé à la main » embrouillait Anass (28/11/2026) : retiré.
        self.assertNotIn("/outils-un#a-la-main", absents)
        self.assertIn("la commande velociraptor", absents)

    def test_barre_de_recherche(self):
        with mock.patch.object(graphiques, "etat",
                               return_value={"present": False, "en_marche": None}):
            p = interface_graphiques.page()
        self.assertIn("id=\"recherche\"", p)
        self.assertIn("data-nom='Velociraptor'", p)
        self.assertIn("startsWith(q)", p)

    def test_page_rien_d_installe(self):
        with mock.patch.object(graphiques, "etat",
                               return_value={"present": False, "en_marche": None}):
            p = interface_graphiques.page()
        self.assertIn("Prêts à ouvrir (0)", p)
        self.assertIn("Aucun de ces outils", p)

    def test_suivi_redirige(self):
        with tempfile.TemporaryDirectory() as d:
            fiche = {"genre": "lien", "url": "https://exemple.org/x", "note": ""}
            with mock.patch.dict(graphiques.INTERFACES, {"InVID-WeVerify": fiche}):
                ident = interface_graphiques.lancer("nom=InVID-WeVerify", journal=d)
                for _ in range(50):
                    if interface_graphiques.OUVERTURES[ident]["etat"] != "en_cours":
                        break
                    time.sleep(0.05)
            p = interface_graphiques.page_suivi(ident)
        self.assertIn('location.replace("https://exemple.org/x")', p)
        self.assertIsNone(interface_graphiques.page_suivi("inexistant"))

    def test_lancer_refuse_sans_case(self):
        with self.assertRaises(graphiques.Refus):
            interface_graphiques.lancer("nom=Shannon")


if __name__ == "__main__":
    unittest.main()


class OutilsDockerEtJetons(unittest.TestCase):
    """Retours de la VM du 28/11/2026 : ARTEX « pas installé » sans dire pourquoi,
    mitmproxy en page d'erreur, Shannon bloqué dans un terminal vide."""

    def setUp(self):
        graphiques._CACHE_ETAT_DOCKER.update(quand=0.0, etat="")

    tearDown = setUp

    def test_artex_dit_que_docker_manque(self):
        with mock.patch.object(graphiques, "docker_etat", return_value="absent"):
            manque = graphiques.manques("ARTEX")
            self.assertFalse(graphiques.etat("ARTEX")["present"])
        self.assertTrue(any("Docker n'est pas installé" in m for m in manque))

    def test_artex_present_avec_docker_et_dossier(self):
        with tempfile.TemporaryDirectory() as racine:
            os.makedirs(os.path.join(racine, "artex"))
            open(os.path.join(racine, "artex", "docker-compose.yml"), "w").close()
            with mock.patch.object(graphiques, "docker_etat", return_value="ok"), \
                    mock.patch.object(graphiques, "_dossiers_outils", return_value=[racine]), \
                    mock.patch.object(graphiques, "repond", return_value=False):
                self.assertEqual(graphiques.manques("ARTEX"), [])
                self.assertTrue(graphiques.etat("ARTEX")["present"])

    def test_env_cree_avec_mots_de_passe_au_hasard(self):
        with tempfile.TemporaryDirectory() as dossier:
            with open(os.path.join(dossier, ".env.example"), "w") as f:
                f.write("POSTGRES_USER=artex\nPOSTGRES_PASSWORD=change-me-please\n"
                        "ARTEX_SECRET_KEY=\nANTHROPIC_API_KEY=\n")
            self.assertIn(".env", graphiques.preparer_env(dossier))
            texte = open(os.path.join(dossier, ".env")).read()
            self.assertNotIn("change-me", texte)
            self.assertRegex(texte, r"POSTGRES_PASSWORD=[\w-]{20,}\n")
            self.assertIn("ARTEX_SECRET_KEY=\n", texte)      # vide = l'outil le crée
            # Un .env existant n'est jamais touché.
            self.assertEqual(graphiques.preparer_env(dossier), "")

    def test_jeton_mitmproxy_lu_dans_le_journal(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("[12:00] HTTP(S) proxy listening at *:8080.\n"
                    "[12:00] Web server listening at http://127.0.0.1:8081/?token=ab12Cd\n")
        try:
            self.assertEqual(graphiques._url_avec_jeton("http://127.0.0.1:8081", f.name),
                             "http://127.0.0.1:8081/?token=ab12Cd")
            self.assertEqual(graphiques._url_avec_jeton("http://127.0.0.1:9999", f.name),
                             "http://127.0.0.1:9999")
        finally:
            os.unlink(f.name)

    def test_shannon_refuse_sans_docker(self):
        from vigie import cles_ia
        with mock.patch.object(graphiques, "docker_etat", return_value="arrete"), \
                mock.patch.object(cles_ia, "lire", return_value={"fournisseur": "openai"}), \
                mock.patch.object(graphiques, "commande_dispo", return_value=["shannon"]), \
                mock.patch.object(graphiques, "npx22", return_value="/x/npx"):
            self.assertFalse(graphiques.etat("Shannon")["present"])
            with self.assertRaises(graphiques.Refus) as refus:
                graphiques.ouvrir("Shannon", engagement=True,
                                  journal=tempfile.mkdtemp())
        self.assertIn("Docker est installé mais arrêté", str(refus.exception))

    def test_terminal_affiche_l_intro_et_le_node_de_vigie(self):
        with mock.patch.object(graphiques, "systeme", return_value="Linux"), \
                mock.patch.object(graphiques.shutil, "which",
                                  side_effect=lambda c: "/usr/bin/xterm" if c == "xterm" else None):
            argv = graphiques._ouvrir_terminal(["/n/bin/npx", "--yes", "x"], "t",
                                               "Patiente.", "/n/bin")
        self.assertIn("echo Patiente.", argv[-1])
        self.assertIn("export PATH=/n/bin:", argv[-1])

    def test_docker_via_sg_si_le_droit_est_donne(self):
        graphiques._CACHE_ETAT_DOCKER.update(quand=graphiques.time.time(), etat="sg")
        self.assertEqual(graphiques._avec_docker(["docker", "compose", "up", "-d"]),
                         ["sg", "docker", "-c", "docker compose up -d"])

    def test_strix_pose_les_questions_puis_lance_la_cible(self):
        fiche = graphiques.INTERFACES["Strix"]
        with mock.patch.object(graphiques, "systeme", return_value="Linux"), \
                mock.patch.object(graphiques.shutil, "which",
                                  side_effect=lambda c: "/usr/bin/xterm" if c == "xterm" else None):
            argv = graphiques._ouvrir_terminal(["/b/strix"], "t", fiche["intro"], "",
                                               fiche["script"])
        self.assertIn('/b/strix --target "$cible"', argv[-1])
        self.assertIn("LLM_API_KEY", argv[-1])
        self.assertIn("docker", fiche["besoin"])

    def test_pentestgpt_demande_la_cle_en_francais(self):
        fiche = graphiques.INTERFACES["PentestGPT"]
        script = fiche["script"].replace("{cmd}", "/b/pentestgpt")
        self.assertIn("ANTHROPIC_API_KEY", script)
        self.assertIn("Colle ta clé d'IA", script)
        self.assertTrue(script.endswith("/b/pentestgpt"))
        import subprocess
        # Syntaxe bash correcte ; avec une clé déjà là, aucune question n'est posée.
        fini = subprocess.run(["bash", "-c", fiche["script"].replace("{cmd}", "echo parti")],
                              env={"PATH": os.environ["PATH"], "OPENAI_API_KEY": "x"},
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(fini.stdout.strip(), "parti")


class CleIA(unittest.TestCase):
    """« Ta clé d'IA » : entrée une fois, gardée, donnée aux seuls outils d'IA (28/11/2026)."""

    def setUp(self):
        self.dossier = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.dossier})
        self.env.start()
        from vigie import cles_ia
        self.cles_ia = cles_ia

    def tearDown(self):
        self.env.stop()

    def test_enregistrer_relire_effacer(self):
        texte = self.cles_ia.enregistrer("anthropic", "sk-ant-api03-abcdefghijkl1234")
        self.assertIn("…1234", texte)
        chemin = self.cles_ia.fichier()
        self.assertTrue(chemin.startswith(self.dossier))          # hors du dépôt
        self.assertEqual(stat.S_IMODE(os.stat(chemin).st_mode), 0o600)
        self.assertEqual(self.cles_ia.environnement()["ANTHROPIC_API_KEY"],
                         "sk-ant-api03-abcdefghijkl1234")
        self.assertNotIn("abcdefghijkl", self.cles_ia.resume())   # jamais réaffichée
        self.cles_ia.effacer()
        self.assertIsNone(self.cles_ia.lire())

    def test_refuse_ce_qui_n_est_pas_une_cle(self):
        for mauvaise in ("trop-court", "sk-ant-'; rm -rf ~; echo '", "sk ant avec espaces 12345"):
            with self.assertRaises(self.cles_ia.Refus):
                self.cles_ia.enregistrer("openai", mauvaise)

    def test_fichier_lisible_par_bash(self):
        import subprocess
        self.cles_ia.enregistrer("openai", "sk-proj-abcdefghijklmnop", "gpt-5")
        fini = subprocess.run(["bash", "-c", f"set -a; . '{self.cles_ia.fichier()}'; "
                               "echo $OPENAI_API_KEY $LLM_API_KEY $STRIX_LLM"],
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(fini.stdout.split(), ["sk-proj-abcdefghijklmnop"] * 2 + ["openai/gpt-5"])

    def test_outil_ia_sans_cle_demande_la_cle_en_francais(self):
        with self.assertRaises(graphiques.Refus) as refus:
            graphiques.ouvrir("PentestGPT", engagement=True, journal=self.dossier)
        self.assertIn("Ta clé d'IA", str(refus.exception))

    def test_cle_donnee_aux_seuls_outils_ia(self):
        self.cles_ia.enregistrer("anthropic", "sk-ant-api03-abcdefghijkl1234")
        self.assertIn("ANTHROPIC_API_KEY", graphiques._environnement("ARTEX"))
        self.assertNotIn("LLM_API_KEY", graphiques._environnement("Wireshark"))

    def test_page_montre_le_formulaire(self):
        with mock.patch.object(graphiques, "etat",
                               return_value={"present": True, "en_marche": None}):
            p = interface_graphiques.page()
        self.assertIn("id=\"cle-ia\"", p)
        self.assertIn("action=\"/ouvrir/cle\"", p)
        self.assertIn("Il lui faut ta clé d'IA", p)            # sur la carte PentestGPT
        p = interface_graphiques.enregistrer_cle(
            "fournisseur=anthropic&cle=sk-ant-api03-abcdefghijkl1234")
        self.assertIn("Clé enregistrée", p)
        self.assertNotIn("abcdefghijkl", p)
