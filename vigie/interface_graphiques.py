"""L'onglet « Ouvrir un outil » : les outils qui ont LEUR interface (fenêtre, page web,
console), ouverts tels quels depuis Vigie. Toute la mécanique est dans graphiques.py.
"""
import html
import secrets
import threading
import urllib.parse

from . import fiches_outils, graphiques, rapport, recettes

OUVERTURES = {}
VERROU = threading.Lock()

CSS = """
.cartes { display:grid; grid-template-columns:repeat(auto-fill,minmax(270px,1fr)); gap:12px;
  margin:10px 0 24px; }
.carte.choisie { outline: 3px solid #1c4e8a; outline-offset: 2px; }
.carte { border:1px solid var(--trait); border-radius:12px; padding:14px 16px; display:grid;
  gap:8px; align-content:start; }
.carte h3 { margin:0; font-size:16px; }
.carte .genre { font-size:12px; color:var(--gris); font-weight:700; text-transform:uppercase;
  letter-spacing:.04em; }
.carte p { margin:0; font-size:14px; }
.carte .note { font-size:13px; color:var(--gris); }
.carte .manque { font-size:13px; color:#8a4b00; background:#fff4e0; border-radius:6px;
  padding:6px 8px; margin:6px 0; }
.carte form { display:grid; gap:8px; margin:0; }
.carte button { font:inherit; font-weight:800; padding:10px 14px; border:0; border-radius:9px;
  background:var(--navy); color:#fff; cursor:pointer; }
.carte button:disabled { background:#cfd6e1; cursor:not-allowed; }
.carte label { font-size:13px; font-weight:600; display:flex; gap:8px; align-items:flex-start; }
.pastille-etat { font-size:11px; font-weight:800; padding:2px 8px; border-radius:6px;
  justify-self:start; }
.e-marche { background:#2e7d4f; color:#fff; }
.e-present { background:#e6f2ec; color:#2e7d4f; }
.e-absent { background:#eceef1; color:#5c6676; }
.fam-avert { padding:10px 14px; border-radius:10px; background:#fcf0dc; color:#7a4b00;
  font-size:14px; }
.fam-avert.gate { background:#fbeceb; color:#8a1d16; }
.recherche { position:relative; margin:18px 0 6px; display:grid; gap:7px; }
.recherche label { font-weight:700; font-size:14px; }
.recherche input { font:inherit; font-size:16px; padding:13px 15px; border:1.5px solid #cfd6e1;
  border-radius:10px; }
.recherche input:focus { outline:none; border-color:var(--navy); }
.suggestions { position:absolute; top:100%; left:0; right:0; z-index:20; list-style:none;
  margin:4px 0 0; padding:6px 0; background:#fff; border:1px solid var(--trait);
  border-radius:10px; box-shadow:0 8px 24px rgba(13,30,56,.15); }
.suggestions li { padding:9px 15px; cursor:pointer; font-size:15px; }
.suggestions li:hover { background:var(--fond); }
.carte.trouvee { outline:3px solid #e3a33b; outline-offset:2px; }
.carte[hidden], .famille-bloc[hidden] { display:none; }
.carte.absente { background:#f6f7f9; border-style:dashed; }
.carte.absente h3 { color:#5c6676; }
.carte .liens { font-size:13.5px; }
.fam-titre { margin:18px 0 6px; font-size:15px; }
details.absents { margin:26px 0 10px; }
details.absents > summary { cursor:pointer; font-weight:800; font-size:17px; padding:10px 0; }
pre.detail { white-space:pre-wrap; font-size:13px; }
"""

TITRES = {
    "diag": "Diagnostic gratuit (OSINT passif)",
    "secu": "Sécurisation et enquête (défensif)",
    "audit": "Audit (outils actifs)",
    "gate": "Offensif (GATE)",
}
AVERTISSEMENTS = {
    "audit": "Outils actifs : les ouvrir ne vise personne, mais ne les pointe que sur ton "
             "labo ou sur une cible couverte par une autorisation signée (art. 323-1 du "
             "Code pénal). Chaque ouverture est notée au journal.",
    "gate": "Outils offensifs : uniquement sur ton labo (serveur d'entraînement) ou sur une "
            "cible couverte par une autorisation signée. Jamais dans un diagnostic. "
            "Chaque ouverture est notée au journal.",
}


def _role(nom):
    fiche = fiches_outils.FICHES.get(nom.lower())
    if fiche and fiche.get("role"):
        return "Ça " + fiche["role"] + "."
    return (graphiques._fiche(nom) or {}).get("categorie", "")


# Recherche : les cartes se filtrent à chaque lettre tapée, et une liste propose les
# noms qui commencent par ces lettres (puis ceux qui les contiennent). Sans accents ni
# majuscules : « wi » trouve Wireshark, « ve » trouve Velociraptor et VeraCrypt.
SCRIPT_RECHERCHE = r"""
(function () {
  // Arrivé d'un clic sur un nom du catalogue (« Lancer un outil ») : sa carte en vue.
  const voulu = new URLSearchParams(location.search).get("outil");
  if (voulu) {
    const carte = Array.from(document.querySelectorAll(".carte"))
      .find(c => c.dataset.nom === voulu);
    if (carte) {
      const replie = carte.closest("details");
      if (replie) { replie.open = true; }
      carte.classList.add("choisie");
      carte.scrollIntoView({block: "center"});
      const bouton = carte.querySelector("button");
      if (bouton) { bouton.focus(); }
    }
  }
})();
(function () {
  const champ = document.getElementById("recherche");
  const liste = document.getElementById("suggestions");
  const rien = document.getElementById("rien");
  const absents = document.querySelector("details.absents");
  const cartes = Array.from(document.querySelectorAll(".carte[data-nom]"));
  const simple = t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  function montrer(carte) {
    if (absents && absents.contains(carte)) absents.open = true;
    carte.scrollIntoView({behavior: "smooth", block: "center"});
    carte.classList.add("trouvee");
    setTimeout(() => carte.classList.remove("trouvee"), 1600);
  }
  function filtrer() {
    const q = simple(champ.value.trim());
    let visibles = 0;
    cartes.forEach(c => {
      const ok = !q || simple(c.dataset.nom).includes(q);
      c.hidden = !ok;
      if (ok) visibles++;
    });
    document.querySelectorAll(".famille-bloc").forEach(b => {
      b.hidden = !b.querySelector(".carte:not([hidden])");
    });
    if (q && absents && absents.querySelector(".carte:not([hidden])")) absents.open = true;
    rien.hidden = !q || visibles > 0;
    liste.innerHTML = "";
    if (!q) { liste.hidden = true; champ.setAttribute("aria-expanded", "false"); return; }
    const debut = cartes.filter(c => simple(c.dataset.nom).startsWith(q));
    const dedans = cartes.filter(c => !debut.includes(c) && simple(c.dataset.nom).includes(q));
    debut.concat(dedans).slice(0, 8).forEach(c => {
      const li = document.createElement("li");
      li.setAttribute("role", "option");
      li.textContent = c.dataset.nom + (c.classList.contains("absente") ? " (pas installé)" : "");
      li.addEventListener("mousedown", ev => { ev.preventDefault(); liste.hidden = true; montrer(c); });
      liste.appendChild(li);
    });
    liste.hidden = !liste.children.length;
    champ.setAttribute("aria-expanded", String(!liste.hidden));
  }
  champ.addEventListener("input", filtrer);
  champ.addEventListener("keydown", ev => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      const premiere = cartes.find(c => !c.hidden);
      if (premiere) { liste.hidden = true; montrer(premiere); }
    } else if (ev.key === "Escape") { champ.value = ""; filtrer(); }
  });
  champ.addEventListener("blur", () => setTimeout(() => { liste.hidden = true; }, 150));
  champ.addEventListener("focus", () => { if (champ.value) filtrer(); });
})();
"""


def _carte(nom, etat):
    """Carte d'un outil PRÉSENT sur la machine : bouton « Ouvrir »."""
    e = html.escape
    fiche = graphiques.INTERFACES[nom]
    if fiche["genre"] in ("page", "lien"):
        pastille = "<span class='pastille-etat e-present'>dans le navigateur</span>"
    elif etat["en_marche"]:
        pastille = "<span class='pastille-etat e-marche'>en marche</span>"
    else:
        pastille = "<span class='pastille-etat e-present'>installé</span>"
    case = ""
    if graphiques.demande_engagement(nom):
        case = ("<label><input type='checkbox' name='engagement' value='oui' required>"
                "Je ne vise que mes propres cibles (mon domaine, mon labo) ou une cible "
                "couverte par une autorisation signée.</label>")
    note = f"<p class='note'>{e(fiche['note'])}</p>" if fiche.get("note") else ""
    return (f"<div class='carte' data-nom='{e(nom)}'><span class='genre'>{e(graphiques.GENRES[fiche['genre']])}"
            f"</span><h3>{e(nom)}</h3>{pastille}<p>{e(_role(nom))}</p>{note}"
            f"<form method='post' action='/ouvrir/lancer' target='_blank'>"
            f"<input type='hidden' name='nom' value='{e(nom)}'>{case}"
            f"<button type='submit'>Ouvrir</button></form></div>")


def _carte_absente(nom):
    """Carte grisée d'un outil que Vigie ne trouve pas : pas de bouton qui promet."""
    e = html.escape
    manque = graphiques.manques(nom)
    pistes = graphiques.pistes(nom)
    if manque:   # ce qui manque, précisément (ex. ARTEX : Docker absent)
        cherche = "".join(f"<p class='manque'>{e(m)}</p>" for m in manque)
    else:
        cherche = (f"<p class='note'>Vigie a cherché {e(', '.join(pistes))}.</p>"
                   if pistes else "")
    raison = recettes.MANUELS.get(nom.lower())
    manuel = (f"<p class='note'>À installer à la main : {e(raison[0])}.</p>"
              if raison else "")
    lien = (graphiques._fiche(nom) or {}).get("lien", "")
    doc = (f"<p class='liens'><a href='{e(lien)}' target='_blank' rel='noopener'>Page "
           f"officielle</a></p>" if lien.startswith("https://") else "")
    return (f"<div class='carte absente' data-nom='{e(nom)}'><span class='genre'>"
            f"{e(graphiques.GENRES[graphiques.INTERFACES[nom]['genre']])}</span>"
            f"<h3>{e(nom)}</h3><span class='pastille-etat e-absent'>pas installé ici</span>"
            f"<p>{e(_role(nom))}</p>{manuel}{cherche}{doc}</div>")


def _blocs(noms, etats, absents=False):
    blocs = []
    for fam in ("diag", "secu", "audit", "gate"):
        liste = [n for n in noms if graphiques.famille(n) == fam]
        if not liste:
            continue
        avert = ""
        if fam in AVERTISSEMENTS and not absents:
            avert = f"<p class='fam-avert {fam}'>{html.escape(AVERTISSEMENTS[fam])}</p>"
        cartes = "".join(_carte_absente(n) if absents else _carte(n, etats[n])
                         for n in liste)
        blocs.append(f"<div class='famille-bloc'><h3 class='fam-titre'>{html.escape(TITRES[fam])} ({len(liste)})"
                     f"</h3>{avert}<div class='cartes'>{cartes}</div></div>")
    return "".join(blocs)


def page(message=""):
    e = html.escape
    bandeau = f"<div class='erreur'>{e(message)}</div>" if message else ""
    noms = graphiques.liste()
    etats = {n: graphiques.etat(n) for n in noms}
    prets = [n for n in noms if etats[n]["present"]]
    absents = [n for n in noms if not etats[n]["present"]]
    if prets:
        partie_prets = _blocs(prets, etats)
    else:
        partie_prets = ("<p class='aide'>Aucun de ces outils n'est encore installé sur "
                        "cette machine.</p>")
    partie_absents = ""
    if absents:
        partie_absents = (
            f"<details class='absents'><summary>Pas encore sur cette machine "
            f"({len(absents)})</summary><p class='aide'>Vigie ne peut pas encore ouvrir "
            "ces outils ici. Sur chaque carte, il dit ce qui manque et quoi faire.</p>"
            f"{_blocs(absents, etats, absents=True)}</details>")
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - Ouvrir un outil</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Ouvrir un outil</h1><div class="meta"><span>Chaque outil avec sa propre interface</span></div></div>
<div class="corps">{bandeau}
<p>Ces outils ont <b>leur propre écran</b>. Un clic sur « Ouvrir » et Vigie fait le
reste : il démarre le logiciel (sa fenêtre apparaît), ou démarre le service et ouvre sa
page web, ou ouvre sa console.</p>
<p class="aide">Les fenêtres s'ouvrent sur l'écran de la machine où tourne Vigie. Si un
service demande les droits administrateur, une fenêtre demande ton mot de passe.</p>
<div class="recherche"><label for="recherche">Chercher un outil</label>
<input id="recherche" type="search" placeholder="Tape les premières lettres : gh, wi, sha…"
 autocomplete="off" autocapitalize="none" role="combobox" aria-controls="suggestions"
 aria-expanded="false">
<ul id="suggestions" class="suggestions" role="listbox" hidden></ul>
<p id="rien" class="aide" hidden>Aucun outil de cet onglet ne porte ce nom.</p></div>
<h2>Prêts à ouvrir ({len(prets)})</h2>
{partie_prets}
{partie_absents}
<p><a href="/">Accueil</a> · <a href="/outils-un">Lancer un outil</a></p></div>
</main><script>{SCRIPT_RECHERCHE}</script></body></html>"""


def lancer(corps, journal=graphiques.JOURNAL):
    """Démarre l'ouverture en arrière-plan. Renvoie l'identifiant de suivi.
    Lève graphiques.Refus (en français) si l'outil ne peut pas s'ouvrir."""
    champs = urllib.parse.parse_qs(corps)
    nom = (champs.get("nom", [""])[0] or "").strip()[:80]
    engagement = champs.get("engagement", [""])[0] == "oui"
    graphiques.verifier(nom, engagement)
    ident = secrets.token_urlsafe(9)
    with VERROU:
        OUVERTURES[ident] = {"outil": nom, "etat": "en_cours", "texte": "Préparation…",
                             "url": "", "detail": ""}

    def suivre(texte):
        with VERROU:
            OUVERTURES[ident]["texte"] = texte

    def travail():
        try:
            fin = graphiques.ouvrir(nom, suivre, engagement=engagement, journal=journal)
            etat = {"etat": "fini", "texte": fin["message"], "url": fin["url"],
                    "detail": fin["detail"], "garder": fin.get("garder", False)}
        except graphiques.Refus as refus:
            etat = {"etat": "erreur", "texte": str(refus)}
        except Exception as erreur:  # la page ne doit jamais rester bloquée
            etat = {"etat": "erreur", "texte": f"Erreur inattendue : {erreur}"}
        with VERROU:
            OUVERTURES[ident].update(etat)
    threading.Thread(target=travail, daemon=True).start()
    return ident


def page_suivi(ident):
    with VERROU:
        etat = dict(OUVERTURES.get(ident) or {})
    if not etat:
        return None
    e = html.escape
    tete, script, lien = "", "", ""
    if etat["etat"] == "en_cours":
        tete = "<meta http-equiv='refresh' content='2'>"
    elif etat["url"]:
        lien = (f"<p><a class='bouton' href='{e(etat['url'])}'>Ouvrir la page de "
                f"{e(etat['outil'])}</a></p>")
        # La page de l'outil remplace cet onglet : l'onglet Vigie reste ouvert à côté.
        if not etat.get("garder"):
            script = f"<script>location.replace({_js(etat['url'])});</script>"
    classe = {"en_cours": "", "fini": " fini", "erreur": " erreur"}[etat["etat"]]
    detail = (f"<details><summary>Détail technique</summary><pre class='detail'>"
              f"{e(etat['detail'])}</pre></details>") if etat.get("detail") else ""
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">{tete}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - {e(etat['outil'])}</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>{e(etat['outil'])}</h1><div class="meta"><span>Ouverture de l'outil</span></div></div>
<div class="corps"><div class="bandeau{classe}">{e(etat['texte'])}</div>{lien}{detail}
<p><a href="/ouvrir">Ouvrir un autre outil</a></p></div></main>{script}</body></html>"""


def _js(texte):
    import json
    return json.dumps(texte).replace("<", "\\u003c")
