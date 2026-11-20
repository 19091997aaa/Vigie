"""La commande Vigie.

    python3 -m vigie diagnostic exemple.fr --societe "Nom de la société"
    python3 -m vigie interface          (ouvre Vigie dans le navigateur)
    python3 -m vigie modules            (les contrôles disponibles)
    python3 -m vigie outils             (les outils externes : installés ou non)
"""
import argparse
import datetime
import os
import re

from . import __version__, autorisation, outils, rapport
from .modeles import Cible, ControleImpossible
from .modules import MODULES, PAR_DEFAUT

DOMAINE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")


def nettoyer_domaine(texte):
    domaine = re.sub(r"^https?://", "", texte.strip().lower()).split("/")[0].rstrip(".")
    if not DOMAINE.fullmatch(domaine):
        raise ValueError(f"Nom de domaine invalide : {texte}")
    return domaine


def lancer(cible, noms_modules, chemin_autorisation=None, date=None):
    """Lance les modules demandés sur la cible et renvoie le rapport (dictionnaire)."""
    date = date or datetime.date.today().isoformat()
    constats, brut, non_realises, trace = [], {}, [], None
    for nom in noms_modules:
        module = MODULES[nom]
        try:
            if module["actif"]:
                trace = autorisation.verifier(chemin_autorisation)
            trouves, donnees = module["fonction"](cible)
            for constat in trouves:
                if not constat.sources:
                    constat.sources = [module["nom"]]
        except ControleImpossible as empechement:
            non_realises.append({"module": module["nom"], "raison": str(empechement)})
            continue
        constats += trouves
        brut[nom] = donnees
    return rapport.construire(cible.societe or cible.domaine, cible.domaine, date,
                              constats, brut, non_realises, trace)


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
                      help="liste séparée par des virgules, ou « tous »")
    diag.add_argument("--pseudo", action="append", default=[],
                      help="pseudo du dirigeant, donné par lui (répétable)")
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

    inst = commandes.add_parser("installer", help="installer en masse les outils du catalogue")
    inst.add_argument("--categorie", help="n'installer qu'une catégorie (nom exact)")
    inst.add_argument("--tous", action="store_true", help="tout le catalogue")
    inst.add_argument("--a-blanc", action="store_true",
                      help="n'installe rien : affiche ce qui serait tenté")
    inst.add_argument("--limite", type=int, help="s'arrêter après N outils (pour essayer)")
    inst.add_argument("--rapport", default="installation.json",
                      help="fichier où écrire le compte rendu")

    commandes.add_parser("modules", help="lister les contrôles disponibles")
    commandes.add_parser("outils", help="lister les outils externes")
    commandes.add_parser("questionnaire", help="afficher le questionnaire assureur")

    args = analyseur.parse_args(arguments)

    if args.commande == "installer":
        from . import installeur
        outils_catalogue = installeur.charger()
        if not args.categorie and not args.tous:
            print("Catégories du catalogue (utilise --categorie \"...\" ou --tous) :\n")
            for nom, nombre in sorted(installeur.categories(outils_catalogue).items(),
                                      key=lambda couple: -couple[1]):
                print(f"  {nombre:4}  {nom}")
            return
        choisis = (outils_catalogue if args.tous else
                   [o for o in outils_catalogue if o["categorie"] == args.categorie])
        if not choisis:
            raise SystemExit(f"Aucun outil dans la catégorie : {args.categorie}")
        if args.limite:
            choisis = choisis[:args.limite]
        print(f"{len(choisis)} outils à traiter"
              + (" (à blanc, rien ne sera installé)" if args.a_blanc else "") + "\n")
        comptes = installeur.installer(choisis, args.a_blanc)
        bilan = installeur.resume(comptes)
        import json as _json
        with open(args.rapport, "w", encoding="utf-8") as fichier:
            _json.dump({"resume": bilan, "details": comptes}, fichier,
                       ensure_ascii=False, indent=2)
        print(f"\nBilan : {bilan['installes']} installés, {bilan['echecs']} en échec "
              f"sur {bilan['total']}.")
        for methode, nombre in bilan["par_methode"].items():
            print(f"  {nombre:4}  via {methode}")
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
        return

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
    noms = list(MODULES) if args.modules.strip() == "tous" else [
        nom.strip() for nom in args.modules.split(",") if nom.strip()]
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
    cible = Cible(domaine, args.societe, args.pseudo, args.accord_dirigeant, reponses)
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
