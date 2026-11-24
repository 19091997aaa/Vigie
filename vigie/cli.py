"""La commande Vigie.

    python3 -m vigie diagnostic exemple.fr --societe "Nom de la société"
    python3 -m vigie interface          (ouvre Vigie dans le navigateur)
    python3 -m vigie modules            (les contrôles disponibles)
    python3 -m vigie outils             (les outils externes : installés ou non)
"""
import argparse
import concurrent.futures
import datetime
import os
import re
import time

from . import __version__, autorisation, outils, rapport
from .modeles import Cible, ControleImpossible
from .modules import COMPLET, MODULES, PAR_DEFAUT

DOMAINE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")


def nettoyer_domaine(texte):
    domaine = re.sub(r"^https?://", "", texte.strip().lower()).split("/")[0].rstrip(".")
    if not DOMAINE.fullmatch(domaine):
        raise ValueError(f"Nom de domaine invalide : {texte}")
    return domaine


# Combien de contrôles tournent en même temps, et combien ouvrent un navigateur à la fois.
PARALLELES = 6
NAVIGATEURS = 2
DELAI_DEFAUT = 600


def _un_controle(cible, nom, chemin_autorisation):
    """Lance UN contrôle. Renvoie (constats, données, trace d'autorisation)."""
    module = MODULES[nom]
    trace = autorisation.verifier(chemin_autorisation) if module["actif"] else None
    trouves, donnees = module["fonction"](cible)
    for constat in trouves:
        if not constat.sources:
            constat.sources = [module["nom"]]
    return trouves, donnees, trace


def _duree(secondes):
    secondes = int(round(secondes))
    return f"{secondes} s" if secondes < 60 else f"{secondes // 60} min {secondes % 60:02d} s"


def lancer(cible, noms_modules, chemin_autorisation=None, date=None, suivi=None,
           paralleles=PARALLELES):
    """Lance les modules demandés sur la cible et renvoie le rapport (dictionnaire).

    Les contrôles tournent en parallèle (paralleles à la fois, NAVIGATEURS au plus qui
    ouvrent Chrome). Un contrôle qui dépasse son délai est abandonné et noté « non
    réalisé » ; un contrôle qui plante aussi : les autres continuent. Un contrôle marqué
    « apres » attend ceux dont il relit les résultats (cible.indices).

    suivi (facultatif) : fonction appelée à chaque étape, pour l'affichage en direct.
    suivi(nom_du_module, etat, detail) avec etat = "en_cours", "fini",
    "non_realise" (contrôle impossible, raison dans detail) ou "echec" (plantage).
    """
    from . import indices
    indices.oublier()
    date = date or datetime.date.today().isoformat()
    suivi = suivi or (lambda *_: None)
    resultats, deroule, trace = {}, [], None
    en_attente, en_cours, termines = list(noms_modules), {}, set()
    groupe = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, paralleles))

    def pret(nom):
        return all(avant in termines or avant not in noms_modules
                   for avant in MODULES[nom].get("apres", ()))

    def terminer(nom, debut, etat, detail, resultat=None):
        duree = time.monotonic() - debut
        termines.add(nom)
        resultats[nom] = resultat
        deroule.append({"module": nom, "nom": MODULES[nom]["nom"], "etat": etat,
                        "detail": detail, "duree": round(duree, 1)})
        suivi(nom, etat, detail if etat != "fini" else f"{detail} — {_duree(duree)}")

    try:
        while en_attente or en_cours:
            navigateurs = sum(1 for n, _ in en_cours.values() if MODULES[n].get("chrome"))
            for nom in list(en_attente):
                if len(en_cours) >= paralleles:
                    break
                if not pret(nom) or (MODULES[nom].get("chrome") and navigateurs >= NAVIGATEURS):
                    continue
                en_attente.remove(nom)
                navigateurs += bool(MODULES[nom].get("chrome"))
                suivi(nom, "en_cours", "")
                tache = groupe.submit(_un_controle, cible, nom, chemin_autorisation)
                en_cours[tache] = (nom, time.monotonic())
            if not en_cours:  # rien ne peut démarrer : ne devrait pas arriver
                for nom in en_attente:
                    terminer(nom, time.monotonic(), "non_realise", "contrôle préalable absent")
                break
            finis, _ = concurrent.futures.wait(
                en_cours, timeout=2, return_when=concurrent.futures.FIRST_COMPLETED)
            for tache in finis:
                nom, debut = en_cours.pop(tache)
                try:
                    trouves, donnees, trace_module = tache.result()
                except ControleImpossible as empechement:
                    terminer(nom, debut, "non_realise", str(empechement))
                    continue
                except Exception as erreur:  # un outil qui plante n'arrête pas les autres
                    terminer(nom, debut, "echec",
                             f"erreur inattendue : {erreur or erreur.__class__.__name__}")
                    continue
                trace = trace_module or trace
                cible.indices[nom] = donnees
                terminer(nom, debut, "fini", f"{len(trouves)} point(s) relevé(s)",
                         (trouves, donnees))
            for tache, (nom, debut) in list(en_cours.items()):
                limite = MODULES[nom].get("delai", DELAI_DEFAUT) + 60
                if time.monotonic() - debut > limite:
                    del en_cours[tache]
                    terminer(nom, debut, "non_realise",
                             f"abandonné : plus de {_duree(limite)} sans réponse")
    finally:
        groupe.shutdown(wait=False, cancel_futures=True)

    constats, brut, non_realises = [], {}, []
    for element in sorted(deroule, key=lambda e: noms_modules.index(e["module"])):
        nom = element["module"]
        if element["etat"] == "fini":
            trouves, donnees = resultats[nom]
            constats += trouves  # dans l'ordre demandé : la fusion garde le premier texte
            brut[nom] = donnees
        else:
            non_realises.append({"module": element["nom"], "raison": element["detail"]})
    resultat = rapport.construire(cible.societe or cible.domaine, cible.domaine, date,
                                  constats, brut, non_realises, trace)
    resultat["deroule"] = deroule
    if any(nom not in PAR_DEFAUT for nom in noms_modules):
        # Diagnostic complet : une ligne par outil des 42, même ceux qui n'ont pas tourné.
        from . import diag_gratuit
        resultat["outils_diag"] = diag_gratuit.bilan(deroule)
    return resultat


def dossier_rapport(sortie, resultat):
    return os.path.join(sortie, f"{resultat['cible'].replace('.', '_')}_{resultat['date']}")


def main(arguments=None):
    analyseur = argparse.ArgumentParser(
        prog="vigie", description=f"Vigie {__version__} - diagnostic de sécurité")
    commandes = analyseur.add_subparsers(dest="commande", required=True)

    diag = commandes.add_parser("diagnostic", help="lancer un diagnostic sur un nom de domaine")
    diag.add_argument("domaine", help="exemple.fr")
    diag.add_argument("--societe", default="", help="nom de la société, pour le rapport")
    diag.add_argument("--modules", default=",".join(PAR_DEFAUT),
                      help="liste séparée par des virgules, « tous », ou « complet » "
                           "(les 42 outils du diagnostic gratuit, plus long)")
    diag.add_argument("--complet", action="store_true",
                      help="diagnostic complet : les 42 outils du diagnostic gratuit")
    diag.add_argument("--pseudo", action="append", default=[],
                      help="pseudo du dirigeant, donné par lui (répétable)")
    diag.add_argument("--mail", action="append", default=[],
                      help="adresse mail du dirigeant, donnée par lui (répétable)")
    diag.add_argument("--telephone", action="append", default=[],
                      help="numéro du dirigeant, donné par lui (répétable)")
    diag.add_argument("--accord-dirigeant", action="store_true",
                      help="le dirigeant a donné son accord écrit pour chercher ses comptes")
    diag.add_argument("--autorisation", help="autorisation signée du client (fichier)")
    diag.add_argument("--reponses", help="réponses au questionnaire assureur (fichier JSON)")
    diag.add_argument("--pdf", action="store_true",
                      help="produire aussi les rapports en PDF (via Chrome/Edge déjà installé)")
    diag.add_argument("--sortie", default="rapports", help="dossier où écrire les rapports")

    interface = commandes.add_parser("interface", help="ouvrir Vigie dans le navigateur")
    interface.add_argument("--port", type=int, default=8765)
    interface.add_argument("--reseau-local", action="store_true",
                           help="rendre Vigie joignable depuis le téléphone, sur le même Wi-Fi")
    interface.add_argument("--sortie", default="rapports")

    comp = commandes.add_parser("comparer", help="comparer ce que plusieurs outils trouvent")
    comp.add_argument("domaine", help="exemple.fr")
    comp.add_argument("--societe", default="")
    comp.add_argument("--modules", default="mail,checkdmarc",
                      help="outils à comparer, séparés par des virgules")
    comp.add_argument("--sortie", default="comparaisons")

    duel = commandes.add_parser("duel", help="banc de comparaison : une question, plusieurs outils")
    duel.add_argument("question", help="sous_domaines, comptes_pseudo, protections_site, mail, "
                                       "chiffrement, logiciels_troues, secrets")
    duel.add_argument("--cible", default="", help="nom de domaine")
    duel.add_argument("--pseudo", default="", help="pseudo du dirigeant, donné par lui")
    duel.add_argument("--accord-dirigeant", action="store_true")
    duel.add_argument("--dossier", default="", help="dossier à lire (logiciels, secrets)")
    duel.add_argument("--sortie", default="comparaisons")

    dec = commandes.add_parser("decouvrir",
                               help="lire l'aide des outils installés pour deviner leur lancement")
    dec.add_argument("--outils", help="commandes séparées par des virgules (sinon : le catalogue)")
    dec.add_argument("--rapport", default="declarations.json",
                     help="fichier où écrire les propositions")

    lan = commandes.add_parser("lancer", help="lancer tous les outils d'une facette sur une cible")
    lan.add_argument("domaine", help="exemple.fr")
    lan.add_argument("--facette", default="domaines", help="domaines, mails, ip, failles ou urls")
    lan.add_argument("--outils", help="liste d'outils séparée par des virgules (sinon : tous)")
    lan.add_argument("--delai", type=int, default=300, help="secondes avant d'abandonner un outil")
    lan.add_argument("--sortie", default="sorties", help="dossier où écrire une sortie par outil")
    lan.add_argument("--sans-banc", action="store_true", help="ne pas mesurer après le lancement")

    bn = commandes.add_parser("banc", help="mesurer quels outils apportent quoi (meilleur mélange)")
    bn.add_argument("--dossier", required=True,
                    help="dossier de sorties d'outils : un fichier par outil, nommé comme lui")
    bn.add_argument("--facette", default="domaines",
                    help="domaines, mails, ip, failles ou urls")
    bn.add_argument("--rapport", default="banc.json", help="fichier où écrire le compte rendu")

    inst = commandes.add_parser("installer", help="installer en masse les outils du catalogue")
    inst.add_argument("--categorie", help="n'installer qu'une catégorie (nom exact)")
    inst.add_argument("--famille", choices=["diag", "audit", "secu", "gate"],
                      help="n'installer qu'une famille (diag = diagnostic gratuit, etc.)")
    inst.add_argument("--tous", action="store_true", help="tout le catalogue")
    inst.add_argument("--a-blanc", action="store_true",
                      help="n'installe rien : affiche ce qui serait tenté")
    inst.add_argument("--limite", type=int, help="s'arrêter après N outils (pour essayer)")
    inst.add_argument("--parallele", type=int, default=8,
                      help="nombre d'installations menées de front (8 par défaut, 1 = à la file)")
    inst.add_argument("--rapport", default="installation.json",
                      help="fichier où écrire le compte rendu")
    inst.add_argument("--dest", help="dossier où poser TOUS les outils (ex. /opt/vigie-outils) : "
                      "évite d'avoir à régler soi-même PIPX_HOME, GOPATH, GOBIN et le PATH")
    inst.add_argument("--reprendre", metavar="RAPPORT",
                      help="fichier rapport d'une install précédente : ne réessaie QUE les "
                      "outils qui avaient échoué (relance ciblée, bien plus rapide)")

    commandes.add_parser("modules", help="lister les contrôles disponibles")
    commandes.add_parser("outils", help="lister les outils externes")
    reg = commandes.add_parser("registre",
                               help="lister TOUS les outils du catalogue, par famille")
    reg.add_argument("familles", nargs="*", help="diag, audit, secu, gate (sinon : toutes)")
    unp = commandes.add_parser("outil",
                               help="lancer UN outil passif, seul, sur une cible")
    unp.add_argument("--nom", required=True, help="nom de l'outil (voir « registre »)")
    unp.add_argument("--cible", required=True, help="domaine, pseudo, e-mail… selon l'outil")
    unp.add_argument("--delai", type=int, default=300)
    commandes.add_parser("questionnaire", help="afficher le questionnaire assureur")

    aut = commandes.add_parser("autorisation",
                               help="préparer l'autorisation de tests à faire signer au client")
    aut.add_argument("--societe", required=True)
    aut.add_argument("--representant", required=True, help="la personne qui signe pour la société")
    aut.add_argument("--cible", action="append", required=True,
                     help="domaine ou adresse IP autorisés (répétable)")
    aut.add_argument("--debut", required=True, help="AAAA-MM-JJ")
    aut.add_argument("--fin", required=True, help="AAAA-MM-JJ")
    aut.add_argument("--tests", default="ports,failles", help="ports, failles, manuels")
    aut.add_argument("--prestataire", default="")
    aut.add_argument("--contact", default="", help="contact du client en cas d'incident")
    aut.add_argument("--sortie", default="autorisations")

    pst = commandes.add_parser("poste", help="vérifier cet ordinateur (virus, outils de pirates, réglages)")
    pst.add_argument("--dossier", default="~", help="dossier à lire (par défaut : le dossier perso)")
    pst.add_argument("--sans-mise-a-jour", action="store_true",
                     help="ne pas mettre à jour la base de virus et les règles avant")

    man = commandes.add_parser("manuel", help="lancer un outil manuel (actif), sur autorisation")
    man.add_argument("--outil", required=True, help="nmap ou nuclei")
    man.add_argument("--cible", required=True)
    man.add_argument("--fiche", required=True, help="autorisation_<n°>.json préparée par Vigie")
    man.add_argument("--signee", required=True, help="l'autorisation signée (scan ou PDF)")
    man.add_argument("--confirmer", default="", help="retaper la cible pour confirmer")
    man.add_argument("--journal", default="journal")

    args = analyseur.parse_args(arguments)

    if args.commande == "decouvrir":
        from . import decouverte, installeur
        import shutil as _shutil
        if args.outils:
            noms = [n.strip() for n in args.outils.split(",") if n.strip()]
        else:
            noms = sorted({o["nom"].split()[0].lower() for o in installeur.charger()})
        presents = [n for n in noms if _shutil.which(n)]
        print(f"{len(noms)} outils examinés, {len(presents)} installés sur cette machine.\n")
        if not presents:
            raise SystemExit("Aucun de ces outils n'est installé : "
                             "python3 -m vigie installer --categorie \"...\"")
        propositions = [decouverte.proposer(nom) for nom in presents]
        print(decouverte.en_texte(propositions))
        import json as _json
        with open(args.rapport, "w", encoding="utf-8") as fichier:
            _json.dump(propositions, fichier, ensure_ascii=False, indent=2)
        print(f"\nPropositions écrites : {args.rapport}")
        return

    if args.commande == "lancer":
        from . import banc, lanceur
        try:
            cible_domaine = nettoyer_domaine(args.domaine)
        except ValueError as erreur:
            raise SystemExit(str(erreur))
        noms = ([n.strip() for n in args.outils.split(",") if n.strip()] if args.outils
                else lanceur.pour_facette(args.facette))
        if not noms:
            raise SystemExit(f"Aucun outil déclaré pour la facette : {args.facette}")
        manquants = [n for n in noms if not lanceur.installe(n)]
        print(f"{len(noms)} outils déclarés pour « {args.facette} », "
              f"{len(noms) - len(manquants)} installés.")
        if manquants:
            print("  absents (ignorés) : " + ", ".join(manquants))
        comptes = lanceur.lancer_tous(noms, cible_domaine, args.sortie, args.delai)
        lances = [c for c in comptes if c["lance"]]
        if not lances:
            raise SystemExit("\nAucun outil n'a pu être lancé. Installe-les d'abord : "
                             "python3 -m vigie installer")
        print(f"\n{len(lances)} outils lancés, sorties dans {args.sortie}/")
        if args.sans_banc:
            return
        # Un outil sorti en erreur n'a rien mesuré : l'inclure ferait passer son message
        # d'erreur (qui contient la cible) pour une trouvaille.
        echoues = [c["outil"] for c in lances if c.get("echoue")]
        exploitables = [c for c in lances if not c.get("echoue")]
        if echoues:
            print("  écartés de la mesure (sortis en erreur ou sans résultat) : "
                  + ", ".join(echoues))
        if not exploitables:
            raise SystemExit("\nAucun outil n'a produit de résultat exploitable.")
        sorties = {}
        for compte in exploitables:
            chemin = os.path.join(args.sortie, f"{compte['outil']}.txt")
            with open(chemin, encoding="utf-8", errors="replace") as fichier:
                sorties[compte["outil"]] = fichier.read()
        mesure = banc.mesurer(sorties, args.facette, exclure=[cible_domaine])
        melange = banc.meilleur_melange(mesure)
        print("\n" + banc.en_texte(mesure, melange))
        temps = lanceur.temps_par_outil(comptes)
        print("\nTEMPS DE CHAQUE OUTIL (un outil lent qui apporte peu est un mauvais marché)")
        for nom, secondes in sorted(temps.items(), key=lambda c: -c[1]):
            if nom in mesure["uniques"]:
                print(f"  {nom:18} {secondes:7} s   {len(mesure['uniques'][nom]):4} trouvailles "
                      "qu'il est seul à voir")
            else:
                print(f"  {nom:18} {secondes:7} s   (écarté : aucun résultat)")
        return

    if args.commande == "banc":
        from . import banc
        if not os.path.isdir(args.dossier):
            raise SystemExit(f"Dossier introuvable : {args.dossier}")
        sorties = {}
        for nom_fichier in sorted(os.listdir(args.dossier)):
            chemin = os.path.join(args.dossier, nom_fichier)
            if not os.path.isfile(chemin):
                continue
            try:
                with open(chemin, encoding="utf-8", errors="replace") as fichier:
                    sorties[os.path.splitext(nom_fichier)[0]] = fichier.read()
            except OSError as erreur:
                print(f"  (ignoré : {nom_fichier} — {erreur})")
        if not sorties:
            raise SystemExit(f"Aucune sortie d'outil lisible dans {args.dossier}")
        try:
            mesure = banc.mesurer(sorties, args.facette)
        except ValueError as erreur:
            raise SystemExit(str(erreur))
        melange = banc.meilleur_melange(mesure)
        print(banc.en_texte(mesure, melange))
        import json as _json
        with open(args.rapport, "w", encoding="utf-8") as fichier:
            _json.dump({
                "facette": mesure["facette"],
                "par_outil": {n: sorted(t) for n, t in mesure["par_outil"].items()},
                "uniques": {n: sorted(t) for n, t in mesure["uniques"].items()},
                "union": sorted(mesure["union"]),
                "melange": melange,
            }, fichier, ensure_ascii=False, indent=2)
        print(f"\nCompte rendu écrit : {args.rapport}")
        return

    if args.commande == "installer":
        from . import installeur, registre
        if getattr(args, "dest", None):
            bin_dir = installeur.preparer_dest(args.dest)
            print(f"Outils posés dans {args.dest} (exécutables : {bin_dir})\n")
        outils_catalogue = installeur.charger()
        if not args.categorie and not args.tous and not args.famille:
            print("Choisis : --famille diag|audit|secu|gate, --categorie \"...\", ou --tous\n")
            print("Familles :")
            for fam, liste in registre.par_famille().items():
                print(f"  {len(liste):4}  {fam} — {registre.FAMILLES[fam]}")
            print("\nCatégories :")
            for nom, nombre in sorted(installeur.categories(outils_catalogue).items(),
                                      key=lambda couple: -couple[1]):
                print(f"  {nombre:4}  {nom}")
            return
        if args.famille:
            noms_famille = {o["nom"].lower() for o in registre.par_famille()[args.famille]}
            choisis = [o for o in outils_catalogue if o["nom"].lower() in noms_famille]
        elif args.tous:
            choisis = outils_catalogue
        else:
            choisis = [o for o in outils_catalogue if o["categorie"] == args.categorie]
        # On n'installe jamais les outils payants (Robin, uncover, PentAGI, mcp-scan…).
        payants = registre.noms_payants()
        avant = len(choisis)
        choisis = [o for o in choisis if o["nom"].lower() not in payants]
        if avant - len(choisis):
            print(f"({avant - len(choisis)} outils payants écartés)")
        if not choisis:
            raise SystemExit(f"Aucun outil pour : {args.famille or args.categorie}")
        # Relance ciblée : on garde les outils déjà prêts tels quels, on ne réessaie
        # que ceux qui avaient échoué. Beaucoup plus rapide qu'une install complète.
        anciens_ok = []
        if getattr(args, "reprendre", None) and os.path.exists(args.reprendre):
            import json as _json
            with open(args.reprendre, encoding="utf-8") as fichier:
                precedent = _json.load(fichier)
            details = precedent.get("details", [])
            # Seuls les outils PRÊTS (installés ET qui démarrent) sont gardés : ceux qui
            # « ne démarraient pas » sont revérifiés (souvent, on cherchait le mauvais nom
            # de commande : clamav au lieu de clamscan).
            anciens_ok = [d for d in details if d.get("installe") and d.get("repond")]
            deja = {d["nom"] for d in anciens_ok}
            avant_reprise = len(choisis)
            choisis = [o for o in choisis if o["nom"] not in deja]
            print(f"Reprise : {len(deja)} outils déjà prêts gardés, "
                  f"{avant_reprise - len(choisis)} ignorés ; {len(choisis)} à réessayer.\n")
        if args.limite:
            choisis = choisis[:args.limite]
        print(f"{len(choisis)} outils à traiter"
              + (" (à blanc, rien ne sera installé)" if args.a_blanc else "")
              + (f", {args.parallele} à la fois" if args.parallele > 1 and not args.a_blanc
                 else "") + "\n")
        debut = time.monotonic()
        nouveaux = installeur.installer(choisis, args.a_blanc, parallele=args.parallele)
        # Le rapport final garde les outils déjà prêts + le résultat des réessais.
        comptes = anciens_ok + nouveaux
        bilan = installeur.resume(comptes)
        import json as _json
        with open(args.rapport, "w", encoding="utf-8") as fichier:
            _json.dump({"resume": bilan, "details": comptes}, fichier,
                       ensure_ascii=False, indent=2)
        minutes = (time.monotonic() - debut) / 60
        print(f"\nBilan sur {bilan['total']} outils, en {minutes:.0f} min :")
        print(f"  {bilan['prets']:4}  prêts (installés ET ils démarrent)")
        print(f"  {bilan['coquilles']:4}  installés mais ne démarrent pas")
        print(f"  {bilan['echecs']:4}  pas installés du tout")
        for methode, nombre in bilan["par_methode"].items():
            print(f"        dont {nombre} via {methode}")
        print(f"Compte rendu écrit : {args.rapport}")
        return

    if args.commande == "modules":
        for nom, module in MODULES.items():
            besoin = "autorisation signée" if module["actif"] else "sans action sur les machines"
            defaut = "par défaut" if module["defaut"] else "sur demande"
            print(f"{nom:9} {module['bloc']:11} {module['nom']} ({besoin}, {defaut})")
        return

    if args.commande == "outils":
        for outil in outils.etat():
            etat = "installé" if outil["installe"] else "absent  "
            branche = "branché" if outil["branche"] else "à brancher"
            genre = "actif" if outil["actif"] else "passif"
            print(f"{outil['nom']:13} {etat}  {branche:10}  {genre:6}  {outil['role']}")
            print(f"{'':13} licence : {outil['licence']} | installation : {outil['installation']}")
        print("\nCe sont les outils de l'enchaînement automatique. Les 216 du catalogue "
              "(clamav, yara, tcpdump…) : « python3 -m vigie registre ».")
        return

    if args.commande == "registre":
        from . import presence, registre
        return registre._principal(args.familles, statut=presence.etat())

    if args.commande == "outil":
        from . import lancer_seul
        try:
            compte = lancer_seul.lancer(args.nom, args.cible, args.delai)
        except lancer_seul.Refus as refus:
            raise SystemExit(str(refus))
        if not compte.get("lance"):
            raise SystemExit(f"Non lancé : {compte.get('raison')}")
        drapeau = "" if compte["verifiee"] else "  (ligne devinée, à confirmer)"
        print(f"{compte['outil']} — {compte['secondes']} s{drapeau}\n")
        print(compte.get("traduction") or "Rien à afficher.")
        return 0

    if args.commande == "autorisation":
        from . import mandat
        try:
            fiche = mandat.creer(args.societe, args.representant, args.cible, args.debut,
                                 args.fin, [t.strip() for t in args.tests.split(",") if t.strip()],
                                 args.prestataire, args.contact)
        except ValueError as erreur:
            print(f"Autorisation non créée : {erreur}")
            return 2
        page, donnees = mandat.ecrire(fiche, args.sortie)
        print(f"Autorisation n° {fiche['numero']} prête.")
        print(f"  À imprimer et faire signer : {page}")
        print(f"  Lue par Vigie              : {donnees}")
        return 0

    if args.commande == "poste":
        from . import poste
        if not args.sans_mise_a_jour:
            poste.preparer()
        try:
            print(poste.en_texte(poste.verifier(args.dossier)))
        except ValueError as erreur:
            print(erreur)
            return 2
        return 0

    if args.commande == "duel":
        from . import duel as banc_duel
        cible = {"domaine": nettoyer_domaine(args.cible) if args.cible else "",
                 "pseudo": args.pseudo, "accord": args.accord_dirigeant, "dossier": args.dossier}
        try:
            resultat = banc_duel.comparer(args.question, cible)
        except ValueError as erreur:
            print(erreur)
            return 2
        print(banc_duel.en_texte(resultat))
        print("\nTableau côte à côte : " + banc_duel.ecrire(resultat, args.sortie))
        return 0

    if args.commande == "manuel":
        from . import manuel
        try:
            chemin = manuel.lancer(args.outil, args.cible, args.fiche, args.signee,
                                   args.confirmer, args.journal)
        except manuel.Refus as refus:
            print(f"Lancement refusé : {refus}")
            return 2
        print(f"Fini. Sortie de l'outil : {chemin} (lancement inscrit au journal)")
        return 0

    if args.commande == "questionnaire":
        from . import questionnaire
        print("Questionnaire assureur — réponds oui/non à chaque question.")
        print("Pour un diagnostic : mets les réponses dans un fichier JSON "
              '{"id": true/false, ...} et passe --reponses ce fichier.\n')
        for question in questionnaire.QUESTIONS:
            print(f"[{question['id']}] ({question['assureurs']})")
            print(f"  {question['question']}\n")
        return

    if args.commande == "interface":
        from . import interface as serveur
        serveur.servir(args.port, args.reseau_local, args.sortie)
        return

    try:
        domaine = nettoyer_domaine(args.domaine)
    except ValueError as erreur:
        raise SystemExit(str(erreur))
    if args.commande == "diagnostic" and args.complet:
        args.modules = "complet"
    if args.modules.strip() == "tous":
        noms = list(MODULES)
    elif args.modules.strip() == "complet":
        noms = list(COMPLET)
    else:
        noms = [nom.strip() for nom in args.modules.split(",") if nom.strip()]
    inconnus = [nom for nom in noms if nom not in MODULES]
    if inconnus:
        raise SystemExit("Module inconnu : " + ", ".join(inconnus))

    if args.commande == "comparer":
        from . import comparaison
        comp = comparaison.comparer(Cible(domaine, args.societe), noms)
        dossier = os.path.join(args.sortie, f"{domaine.replace('.', '_')}_{comp['date']}")
        chemins = comparaison.ecrire(comp, dossier)
        print(comparaison.en_texte(comp))
        print("\nComparaison écrite :")
        for chemin in chemins.values():
            print("  " + chemin)
        return

    reponses = {}
    if args.reponses:
        import json
        try:
            with open(args.reponses, encoding="utf-8") as fichier:
                reponses = json.load(fichier)
        except (OSError, ValueError) as erreur:
            raise SystemExit(f"Réponses illisibles : {erreur}")
        if "conformite" not in noms:
            noms.append("conformite")
    cible = Cible(domaine, args.societe, pseudos=args.pseudo,
                  accord_dirigeant=args.accord_dirigeant, reponses=reponses,
                  emails=args.mail, telephones=args.telephone)
    resultat = lancer(cible, noms, args.autorisation)
    chemins = rapport.ecrire(resultat, dossier_rapport(args.sortie, resultat))
    print(rapport.en_texte(resultat))
    print("Rapports écrits :")
    for chemin in chemins.values():
        print("  " + chemin)
    if args.pdf:
        from . import pdf as export_pdf
        try:
            produits = export_pdf.ecrire_pdf(chemins)
            print("PDF produits :")
            for chemin in produits.values():
                print("  " + chemin)
        except export_pdf.PasDeNavigateur as empechement:
            print("PDF non produit : " + str(empechement))


if __name__ == "__main__":
    main()
