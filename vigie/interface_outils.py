"""L'onglet « Lancer un outil » : choisir UN outil du catalogue et le lancer seul.

On voit les 216 outils non payants rangés par famille, et ceux qui sont INSTALLÉS sur
cette machine (presence.py). Les outils PASSIFS (diag, sécurisation) se lancent ici, un
par un, sur la cible saisie. Les outils ACTIFS ou offensifs ne se lancent PAS ici : ils
renvoient vers l'onglet « Outils manuels », qui exige l'autorisation signée (règles
d'or). Tous les garde-fous sont dans lancer_seul.py.
"""
import html
import urllib.parse
import secrets
import threading

from . import (__version__, avancement, fiches_outils, lancer_seul, manuel, mes_cibles, presence, rapport,
               registre)

LANCEMENTS = {}
SUIVIS = {}          # identifiant -> avancement.Suivi, le temps que l'outil tourne
VERROU = threading.Lock()

CSS = """
.familles { padding: 8px 40px 24px; }
.fam { margin: 22px 0 0; }
.fam h2 { margin: 0 0 10px; }
.liste-outils { display: grid; grid-template-columns: repeat(auto-fill,minmax(230px,1fr));
  gap: 8px 16px; list-style: none; padding: 0; margin: 0; }
.nom-outil { color: var(--encre, #14213d); font: inherit; font-weight: 700;
  text-decoration: underline; text-underline-offset: 3px; background: none; border: 0;
  padding: 0; cursor: pointer; }
.nom-outil:hover { color: #1c4e8a; }
.ouvrir-direct { display: inline; margin: 0; }
.sur-place { display: inline; }
.sur-place summary { display: inline; list-style: none; }
.sur-place summary::-webkit-details-marker { display: none; }
.sur-place[open] form { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0 2px; }
.sur-place input { flex: 1 1 140px; min-width: 0; padding: 6px 8px; font-size: 14px; }
.sur-place button { padding: 6px 12px; font-size: 14px; }
.sur-place-note { font-size: 12px; color: #9a5f00; width: 100%; }
.liste-outils li { font-size: 14px; padding: 6px 0; border-bottom: 1px solid var(--trait); }
.liste-outils .marque { font-size: 11px; font-weight: 800; letter-spacing: .04em;
  padding: 2px 7px; border-radius: 6px; margin-left: 6px; }
.m-auto { background: #fcf0dc; color: #9a5f00; }
.m-payant { background: #eceef1; color: #5c6676; }
.m-pret { background: #e6f2ec; color: #2e7d4f; }
.m-ouvrir { background: #e4edfb; color: #1c4e8a; }
.m-main { background: #eceef1; color: #5c6676; }
.m-installe { background: #2e7d4f; color: #fff; }
.compte-installes { font-size: 15px; margin: 6px 0 0; }
.legende { font-size: 13px; color: #3c4656; margin: 8px 0 0; line-height: 1.9; }
.refus { padding: 13px 16px; border-radius: 10px; border-left: 4px solid #b3261e;
  background: #fbeceb; color: #5a1410; margin: 4px 0 14px; line-height: 1.5; }
.refus b { color: #8a1d16; }
.reussi { padding: 13px 16px; border-radius: 10px; border-left: 4px solid #1e7a46;
  background: #e6f2ec; margin: 4px 0 14px; line-height: 1.5; }
.explication { padding: 13px 16px; border-radius: 10px; border-left: 4px solid #9a5f00;
  background: #fcf0dc; margin: 4px 0 14px; line-height: 1.5; }
.explication p, .reussi p { margin: 4px 0; }
.aide-outil { font-size: 14px; color: #3c4656; margin: -4px 0 10px; min-height: 1.4em; }
details.brut summary { cursor: pointer; font-weight: 700; margin: 12px 0 6px; }
.avancement { padding: 14px 16px; border-radius: 10px; background: #eef3fa;
  border-left: 4px solid #1c4e8a; margin: 4px 0 14px; line-height: 1.5; }
.avancement p { margin: 4px 0; }
.av-chiffre { font-size: 30px; font-weight: 800; color: #1c4e8a; }
.av-sorte { font-size: 13px; font-weight: 700; color: #3c4656; margin-left: 8px; }
.av-barre { height: 14px; border-radius: 7px; background: #d7e1ee; overflow: hidden;
  margin: 8px 0; }
.av-barre span { display: block; height: 100%; background: #1c4e8a;
  transition: width .6s ease; }
.av-barre.av-temps { height: 6px; }
.av-barre.av-temps span { background: #8a96a8; }
.av-barre.av-inconnu span { width: 30%; background: #9db4d3;
  animation: av-va 1.6s ease-in-out infinite alternate; }
@keyframes av-va { from { margin-left: 0; } to { margin-left: 70%; } }
.av-petit { font-size: 13px; color: #3c4656; }
"""


def _champs(corps):
    import urllib.parse
    return urllib.parse.parse_qs(corps, keep_blank_values=True)


def _options_passifs(etats=None):
    """Un <select> des outils passifs non payants, groupés par famille.
    Ceux qui sont installés ici viennent en tête, marqués « ✓ »."""
    etats = etats or {}
    groupes = registre.par_famille()
    etiquettes = {"diag": "Diagnostic gratuit (OSINT passif)",
                  "secu": "Sécurisation (défensif, local)"}
    morceaux = []
    for fam in ("diag", "secu"):
        passifs = [o for o in groupes.get(fam, [])
                   if not o["payant"] and not o["autorisation_requise"]
                   and lancer_seul.lancable_ici(o["nom"])]
        if not passifs:
            continue
        options = "".join(
            _option(o, etats.get(o["nom"]))
            for o in sorted(passifs, key=lambda x: (not etats.get(x["nom"]), x["nom"].lower())))
        morceaux.append(f"<optgroup label='{etiquettes[fam]}'>{options}</optgroup>")
    # Actifs et offensifs : seulement sur MES propres cibles prouvées (mes_cibles.py).
    for fam, etiquette in (("audit", "Actifs : seulement sur mes propres cibles"),
                           ("gate", "Offensifs : seulement sur mes propres cibles")):
        actifs = [o for o in groupes.get(fam, [])
                  if not o["payant"] and o["autorisation_requise"]
                  and lancer_seul.lancable_ici(o["nom"])]
        if actifs:
            options = "".join(
                _option(o, etats.get(o["nom"]))
                for o in sorted(actifs, key=lambda x: (not etats.get(x["nom"]),
                                                       x["nom"].lower())))
            morceaux.append(f"<optgroup label='{etiquette}'>{options}</optgroup>")
    return "".join(morceaux)


def verifier_propre_cible(nom, cible, dossier_cibles):
    """Pour un outil actif ou offensif : la cible doit être une des miennes, prouvée.
    Renvoie True si l'outil peut partir sur cette cible, False s'il est passif.
    Lève lancer_seul.Refus (en français) sinon."""
    fiche = lancer_seul.info(nom)
    if not fiche or not fiche["autorisation_requise"] or fiche["payant"]:
        return False
    hote = lancer_seul.hote(cible)
    if not dossier_cibles or not hote:
        raise lancer_seul.Refus(
            f"{fiche['nom']} est un outil {'offensif' if fiche['attaque'] else 'actif'} : "
            "il ne part que sur une de tes propres cibles prouvées (onglet « Outils "
            "manuels », partie « Mes propres cibles »), ou avec une autorisation signée.")
    raison = mes_cibles.raison_refus(dossier_cibles, hote)
    if raison:
        raise lancer_seul.Refus(raison + " (Tes propres cibles se déclarent dans « Outils "
                                "manuels ».)")
    return True


def aide(o):
    """Une phrase d'aide pour un outil : à quoi il sert et ce qu'il attend."""
    f = fiches_outils.fiche(o["nom"], o)
    role = f.get("role") or o.get("categorie", "")
    if f.get("mode") != "cible":
        quoi = {"service": "service à installer, ne se lance pas d'ici",
                "appli": "logiciel à ouvrir soi-même",
                "windows": "Windows seulement",
                "capture": "capture réseau, à lancer à la main",
                "ressource": "règles pour un autre outil",
                "compte": "demande un compte ou une clé",
                "agent": "compétence pour assistant IA",
                "a_la_main": "demande une préparation"}.get(f["mode"], "à la main")
        return f"Ça {role}. ({quoi})"
    attendu = fiches_outils.CIBLES.get(f.get("cible"))
    if not attendu:
        return f"Ça {role}."
    if f["cible"] == "aucune":
        return f"Ça {role}. Pas de cible à taper."
    return f"Ça {role}. Cible : {attendu[0]}, par exemple {attendu[1]}."


def _option(o, installe):
    e = html.escape
    f = fiches_outils.fiche(o["nom"], o)
    a_la_main = "" if f.get("mode") == "cible" else " (à la main)"
    return (f"<option value='{e(o['nom'])}' data-aide='{e(aide(o), quote=True)}'>"
            f"{'✓ ' if installe else ''}{e(o['nom'])}{a_la_main}"
            f" — {e((f.get('role') or o['categorie'])[:60])}</option>")


def _statut(o, interfaces):
    """L'état réel d'un outil pour l'affichage (classe CSS, texte du badge) :
    lançable ici seulement s'il a une vraie recette ; sinon « à ouvrir » (il a sa propre
    interface) ou « à la main ». Fini le « lançable » promis puis refusé."""
    if o["payant"]:
        return "m-payant", "payant"
    if lancer_seul.lancable_ici(o["nom"]):
        return ("m-auto", "autorisation") if o["autorisation_requise"] else ("m-pret", "lançable")
    if o["nom"] in interfaces:
        return "m-ouvrir", "à ouvrir"
    return "m-main", "à la main"


def _catalogue_html(etats=None):
    from . import graphiques
    etats = etats or {}
    e = html.escape
    interfaces = graphiques.INTERFACES
    groupes = registre.par_famille()
    titres = registre.FAMILLES
    blocs = []
    for fam in registre.ORDRE:
        liste = sorted(groupes.get(fam, []), key=lambda x: x["nom"].lower())
        items = []
        for o in liste:
            classe, texte = _statut(o, interfaces)
            marque = f"<span class='marque {classe}'>{texte}</span>"
            if etats.get(o["nom"]):
                marque += "<span class='marque m-installe'>installé</span>"
            items.append(f"<li>{_nom_cliquable(o, classe, etats)}{marque}</li>")
        installes = sum(1 for o in liste if etats.get(o["nom"]))
        blocs.append(f"<div class='fam'><h2>{e(titres[fam])} ({len(liste)})"
                     f" — {installes} installé{'s' if installes > 1 else ''}</h2>"
                     f"<ul class='liste-outils'>{''.join(items)}</ul></div>")
    return "".join(blocs)


def _lancer_sur_place(o, classe):
    """Clic sur un nom lançable : la case « cible » et le bouton Lancer s'ouvrent JUSTE
    SOUS le nom (Anass, 28/11/2026 : le clic le renvoyait en haut de page et il croyait
    que rien ne partait). Un outil sans cible part au clic. Même route que le formulaire
    du haut : mêmes garde-fous (propres cibles pour « autorisation »)."""
    e = html.escape
    nom = o["nom"]
    f = fiches_outils.fiche(nom, o)
    attendu = fiches_outils.CIBLES.get(f.get("cible"))
    cache = f"<input type='hidden' name='nom' value='{e(nom)}'>"
    if f.get("cible") == "aucune":
        return (f"<form class='ouvrir-direct' method='post' action='/outil/lancer'>{cache}"
                f"<input type='hidden' name='cible' value=''><button type='submit' "
                f"class='nom-outil' title='Lancer {e(nom, quote=True)}'>{e(nom)}</button>"
                f"</form>")
    exemple = attendu[1] if attendu else "exemple.fr"
    quoi = attendu[0] if attendu else "la cible"
    garde = ("<span class='sur-place-note'>Seulement sur tes propres cibles.</span>"
             if classe == "m-auto" else "")
    return (f"<details class='sur-place'><summary class='nom-outil' title='Lancer "
            f"{e(nom, quote=True)}'>{e(nom)}</summary>"
            f"<form method='post' action='/outil/lancer'>{cache}"
            f"<input name='cible' required placeholder='{e(exemple, quote=True)}' "
            f"aria-label='{e(quoi, quote=True)}' title='{e(quoi, quote=True)}'>"
            f"<button type='submit'>Lancer</button>{garde}</form></details>")


def _nom_cliquable(o, classe, etats):
    """Le nom d'un outil dans le catalogue, cliquable quand il peut partir d'ici
    (demande d'Anass, 28/11/2026 : « cliquer dessus, que ça se lance direct ») :
      - lançable : la case cible et le bouton Lancer s'ouvrent sous le nom ;
      - à ouvrir : installé et sans case d'engagement -> s'ouvre tout de suite (sa
        fenêtre ou sa page) ; sinon -> sa carte dans « Ouvrir un outil ».
    Rien n'est lancé sur une cible par un simple lien."""
    from . import graphiques
    e = html.escape
    nom = o["nom"]
    if classe in ("m-pret", "m-auto"):
        return _lancer_sur_place(o, classe)
    if classe == "m-ouvrir":
        if etats.get(nom) and not graphiques.demande_engagement(nom):
            return (f"<form class='ouvrir-direct' method='post' action='/ouvrir/lancer' "
                    f"target='_blank'><input type='hidden' name='nom' value='{e(nom)}'>"
                    f"<button type='submit' class='nom-outil' title='Ouvrir "
                    f"{e(nom, quote=True)} (sa propre interface)'>{e(nom)}</button></form>")
        return (f"<a class='nom-outil' href='/ouvrir?outil={urllib.parse.quote(nom)}' "
                f"title='Voir {e(nom, quote=True)} dans « Ouvrir un outil »'>{e(nom)}</a>")
    return e(nom)


def _formulaire_brancher(etats):
    """« Je l'ai installé à la main » : on montre où est le programme, Vigie le relie."""
    e = html.escape
    manquants = sorted((o["nom"] for o in registre.charger()
                        if not o["payant"] and not etats.get(o["nom"])), key=str.lower)
    if not manquants:
        return ""
    options = "".join(f"<option>{e(nom)}</option>" for nom in manquants)
    return f"""<div class="corps" id="a-la-main"><h2>Je l'ai installé à la main</h2>
<p>Tu as posé un outil toi-même (programme téléchargé, dossier copié depuis GitHub…) ?
Montre à Vigie où il est : Vigie le relie, vérifie qu'il démarre et le marque
<span class='marque m-installe'>installé</span>. Rien n'est téléchargé.</p>
<form method="post" action="/outil/brancher">
<label>Outil<select name="nom">{options}</select></label>
<label>Où est le programme (ou son dossier)
<input name="chemin" placeholder="/home/moi/Téléchargements/chainsaw/chainsaw"></label>
<p class="aide-outil">Astuce : dans le gestionnaire de fichiers, clic droit sur le fichier
&gt; Copier, puis clique dans la case et fais Ctrl+V : le chemin s'écrit tout seul.</p>
<button type="submit">Brancher sur Vigie</button>
</form></div>"""


def brancher(corps):
    """Traite le formulaire « Je l'ai installé à la main ». Renvoie la page avec le
    résultat en français (réussite ou raison du refus)."""
    import urllib.parse
    from . import a_la_main
    champs = urllib.parse.parse_qs(corps)
    nom = champs.get("nom", [""])[0].strip()[:120]
    chemin = champs.get("chemin", [""])[0].strip()[:1000]
    try:
        return page(ok=a_la_main.brancher(nom, chemin))
    except (a_la_main.Refus, OSError) as erreur:
        return page(message=str(erreur))


def page(message="", ok=""):
    bandeau = ""
    if message:
        bandeau = ("<div class='refus'><b>Pourquoi ça ne part pas :</b><br>"
                   f"{html.escape(message)}</div>")
    elif ok:
        bandeau = f"<div class='bandeau'>{html.escape(ok)}</div>"
    etats = presence.etat()
    gratuits = [o["nom"] for o in registre.non_payants()]
    installes = sum(1 for nom in gratuits if etats.get(nom))
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - Lancer un outil</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Lancer un outil</h1><div class="meta"><span>Un outil, une cible, à la demande</span></div></div>
<div class="corps">{bandeau}
<p>Choisis un outil et une cible (domaine, pseudo, e-mail… selon l'outil). Les outils
<b>actifs</b> ou <b>offensifs</b> ne partent que sur <b>tes propres cibles prouvées</b>
(ton domaine, tes machines de labo : à déclarer dans <a href="/manuel">Outils manuels</a>).
Pour toute autre cible, il faut une autorisation signée.</p>
<form method="post" action="/outil/lancer" id="lancer">
<label>Outil<select name="nom" id="choix-outil">{_options_passifs(etats)}</select></label>
<p class="aide-outil" id="aide-outil"></p>
<label>Cible<input name="cible" placeholder="exemple.fr ou un pseudo"></label>
<button type="submit">Lancer cet outil</button>
</form>
<script>
(function () {{
  var choix = document.getElementById("choix-outil");
  var aide = document.getElementById("aide-outil");
  function maj() {{
    var o = choix.options[choix.selectedIndex];
    aide.textContent = o ? (o.getAttribute("data-aide") || "") : "";
  }}
  // Arrivé d'un clic sur un nom du catalogue : l'outil est déjà choisi, reste la cible.
  var voulu = new URLSearchParams(location.search).get("outil");
  if (voulu) {{
    for (var i = 0; i < choix.options.length; i++) {{
      if (choix.options[i].value === voulu) {{ choix.selectedIndex = i; break; }}
    }}
    var cible = document.querySelector("input[name=cible]");
    if (cible) {{ cible.focus(); }}
  }}
  choix.addEventListener("change", maj); maj();
}})();
</script></div>
<div class="familles"><h2>Tous les outils du catalogue</h2>
<p class="compte-installes"><b>{installes}</b> {'outils' if installes > 1 else 'outil'} sur
{len(gratuits)} {'sont installés' if installes > 1 else 'est installé'} sur cette machine
(marqués <span class='marque m-installe'>installé</span>).</p>
<p class="legende"><span class='marque m-pret'>lançable</span> Vigie le lance ici ·
<span class='marque m-auto'>autorisation</span> seulement sur tes propres cibles ·
<span class='marque m-ouvrir'>à ouvrir</span> s'ouvre avec sa propre fenêtre
(<a href="/ouvrir">Ouvrir un outil</a>) ·
<span class='marque m-main'>à la main</span> s'utilise à la main.</p>
{_catalogue_html(etats)}</div>
<div class="corps"><p><a href="/">Accueil</a> · <a href="/manuel">Outils manuels</a></p></div>
</main></body></html>"""


def lancer(corps, dossier_cibles=None, journal="journal"):
    """Lance un outil passif en arrière-plan. Renvoie l'identifiant de suivi.
    Lève lancer_seul.Refus (raison en clair, en français) si le lancement n'est pas
    permis ou ne peut pas marcher : outil actif, service, mauvaise cible…"""
    c = _champs(corps)
    nom = (c.get("nom", [""])[0] or "").strip()[:80]
    cible = (c.get("cible", [""])[0] or "").strip()[:200]
    # Actif ou offensif : seulement sur une propre cible prouvée (sinon refus).
    propre = verifier_propre_cible(nom, cible, dossier_cibles)
    lancer_seul.verifier_lancable(nom, autorisation_ok=propre)  # refuse payant/inconnu
    prepa = lancer_seul.preparer(nom, cible, propre_ok=propre)  # explique tout refus
    if propre:
        # La cible arrangée par Vigie doit rester la même machine.
        if lancer_seul.hote(prepa["cible"]) != lancer_seul.hote(cible):
            verifier_propre_cible(nom, prepa["cible"], dossier_cibles)
        manuel._journal(journal, {"outil": nom, "cible": prepa["cible"],
                                  "autorisation": "propre cible (" + mes_cibles.ATTESTATION
                                  + ")", "resultat": "lancé", "depuis": "Lancer un outil"})
    ident = secrets.token_urlsafe(9)
    suivi = avancement.Suivi(habituel=avancement.habituel(journal, nom))
    with VERROU:
        SUIVIS[ident] = suivi
        LANCEMENTS[ident] = {"etat": "en_cours", "outil": nom,
                             "cible": prepa["cible"] or "cet ordinateur",
                             "resultat": "", "explication": [], "brut": "",
                             "reussi": False, "commande": ""}

    def travail():
        try:
            compte = lancer_seul.lancer(nom, cible, propre_ok=propre, suivi=suivi)
            reussi = bool(compte.get("lance")) and not compte.get("code") \
                and not compte.get("panne") and bool((compte.get("sortie") or "").strip())
            brut = (compte.get("sortie") or "")
            if compte.get("erreurs") and compte["erreurs"] not in brut:
                brut += "\n" + compte["erreurs"]
            if compte.get("absent"):
                brut = "Raison notée à l'installation : " + (
                    lancer_seul.raison_installation(compte["outil"]) or "aucune (pas encore "
                    "d'installation sur cette machine)")
            etat = {"etat": "fini" if compte.get("lance") else "erreur",
                    "outil": compte["outil"], "reussi": reussi,
                    "partiel": bool(compte.get("depasse")),
                    "explication": compte.get("explication", []),
                    "resultat": compte.get("traduction") if reussi else "",
                    "brut": brut.strip(), "commande": compte.get("commande", "")}
            if reussi and not compte.get("depasse"):
                # Durée habituelle : la prochaine fois, Vigie pourra estimer l'avancement.
                avancement.noter(journal, compte["outil"], compte.get("secondes"))
        except Exception as erreur:
            etat = {"etat": "erreur", "explication": [str(erreur)]}
        with VERROU:
            LANCEMENTS[ident].update(etat)
            SUIVIS.pop(ident, None)
    threading.Thread(target=travail, daemon=True).start()
    return ident


def etat_avancement(ident):
    """L'avancement d'un lancement, pour la page (rafraîchie toute seule), ou None."""
    with VERROU:
        etat = LANCEMENTS.get(ident)
        if etat is None:
            return None
        suivi = SUIVIS.get(ident)
        en_cours = etat["etat"] == "en_cours"
    if not en_cours or suivi is None:
        return {"en_cours": False}
    return {"en_cours": True, **suivi.etat()}


def _bloc_avancement(av):
    """Le cadre « où en est l'outil » (rempli ici, puis mis à jour par la page)."""
    e = html.escape
    pourcent = av.get("pourcent")
    if pourcent is None:
        chiffre = ""
        barre = "<div class='av-barre av-inconnu' id='av-barre'><span></span></div>"
    else:
        sorte = "donné par l'outil" if av.get("sorte") == "outil" else "estimation"
        chiffre = (f"<p><span class='av-chiffre' id='av-chiffre'>{pourcent} %</span>"
                   f"<span class='av-sorte' id='av-sorte'>{sorte}</span></p>")
        barre = (f"<div class='av-barre' id='av-barre'><span style='width:{pourcent}%'>"
                 "</span></div>")
    temps = ""
    if av.get("maximum"):
        temps = (f"<p class='av-petit' id='av-temps'>Temps écoulé : {e(av['ecoule'])} · "
                 f"arrêt automatique au bout de {e(av['maximum'])}.</p>"
                 f"<div class='av-barre av-temps'><span id='av-temps-barre' "
                 f"style='width:{av.get('part_delai') or 0}%'></span></div>")
    dernieres = "\n".join(av.get("dernieres") or [])
    return (f"<div class='avancement' id='avancement'>{chiffre}{barre}"
            f"<p id='av-phrase'>{e(av.get('phrase', ''))}</p>"
            f"<p id='av-activite'>{e(av.get('activite', ''))}</p>{temps}"
            "<details class='brut'><summary>Ce que l'outil écrit en ce moment (en anglais)"
            f"</summary><pre id='av-lignes'>{e(dernieres) or '(rien pour l’instant)'}"
            "</pre></details></div>")


# Met le cadre à jour toutes les 2 s sans recharger la page (le repli dépliable reste
# ouvert) ; recharge une seule fois quand l'outil a fini, pour afficher le résultat.
_SCRIPT_AVANCEMENT = """<script>
(function () {
  var adresse = location.pathname.replace(/\\/$/, "") + "/etat";
  function texte(id, valeur) { var n = document.getElementById(id); if (n) n.textContent = valeur; }
  function maj() {
    fetch(adresse, {cache: "no-store"}).then(function (r) { return r.json(); })
    .then(function (av) {
      if (!av.en_cours) { location.reload(); return; }
      var barre = document.getElementById("av-barre");
      if (av.pourcent === null || av.pourcent === undefined) {
        barre.className = "av-barre av-inconnu"; barre.firstChild.style.width = "";
        texte("av-chiffre", ""); texte("av-sorte", "");
      } else {
        barre.className = "av-barre"; barre.firstChild.style.width = av.pourcent + "%";
        texte("av-chiffre", av.pourcent + " %");
        texte("av-sorte", av.sorte === "outil" ? "donné par l'outil" : "estimation");
      }
      texte("av-phrase", av.phrase); texte("av-activite", av.activite);
      if (av.maximum) {
        texte("av-temps", "Temps écoulé : " + av.ecoule + " · arrêt automatique au bout de "
              + av.maximum + ".");
        var t = document.getElementById("av-temps-barre");
        if (t) t.style.width = (av.part_delai || 0) + "%";
      }
      texte("av-lignes", (av.dernieres || []).join("\\n") || "(rien pour l’instant)");
      setTimeout(maj, 2000);
    }).catch(function () { setTimeout(maj, 4000); });
  }
  setTimeout(maj, 2000);
})();
</script>"""


def page_resultat(ident):
    with VERROU:
        etat = dict(LANCEMENTS.get(ident) or {})
    if not etat:
        return None
    e = html.escape
    en_cours = etat["etat"] == "en_cours"
    # Sans JavaScript, la page se recharge seule ; avec, seul le cadre change.
    rafraichir = "<noscript><meta http-equiv='refresh' content='4'></noscript>" \
        if en_cours else ""
    if en_cours:
        titre = "En cours…"
    elif etat.get("reussi"):
        titre = "Résultat partiel (temps maximum atteint)" if etat.get("partiel") \
            else "Terminé"
    else:
        titre = "N'a pas marché" if etat["etat"] == "erreur" or etat.get("explication") \
            else "Terminé"
    morceaux = []
    if en_cours:
        morceaux.append("<p>L'outil tourne. Cette page se met à jour toute seule.</p>")
        av = etat_avancement(ident) or {}
        if av.get("en_cours"):
            morceaux.append(_bloc_avancement(av) + _SCRIPT_AVANCEMENT)
    phrases = etat.get("explication") or []
    if phrases:
        classe = "reussi" if etat.get("reussi") else "explication"
        intro = "" if etat.get("reussi") else "<p><b>Ce qui s'est passé :</b></p>"
        morceaux.append(f"<div class='{classe}'>{intro}"
                        + "".join(f"<p>{e(p)}</p>" for p in phrases) + "</div>")
    if etat.get("resultat"):
        morceaux.append(f"<h2>Résumé</h2><pre>{e(etat['resultat'])}</pre>")
    if etat.get("brut") or etat.get("commande"):
        detail = ""
        if etat.get("commande"):
            detail += f"Commande : {etat['commande']}\n\n"
        detail += etat.get("brut") or ""
        morceaux.append("<details class='brut'><summary>Détail technique (sortie brute de "
                        f"l'outil, en anglais)</summary><pre>{e(detail)}</pre></details>")
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">{rafraichir}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - {e(etat['outil'])}</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>{e(etat['outil'])} sur {e(etat['cible'])}</h1><div class="meta"><span>{titre}</span></div></div>
<div class="corps">{''.join(morceaux)}
<p><a href="/outils-un">Lancer un autre outil</a> · <a href="/">Accueil</a></p></div></main></body></html>"""
