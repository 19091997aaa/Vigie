"""Applique un lot de fiches {nom: {champs}} à docs_outils.json. Outil de chantier, hors package."""
import json, sys, os
CHEMIN = os.path.join(os.path.dirname(__file__), "..", "vigie", "docs_outils.json")
def appliquer(lot):
    fiches = json.load(open(CHEMIN, encoding="utf-8"))
    par_nom = {f["nom"]: f for f in fiches}
    touchees = 0
    for nom, champs in lot.items():
        if nom not in par_nom:
            print(f"  INCONNU: {nom}"); continue
        par_nom[nom].update(champs); par_nom[nom]["statut"] = "lu"; touchees += 1
    json.dump(fiches, open(CHEMIN, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    lus = sum(1 for f in fiches if f["statut"] == "lu")
    print(f"  {touchees} fiches mises à jour | {lus}/{len(fiches)} lues, reste {len(fiches)-lus}")
if __name__ == "__main__":
    appliquer(json.load(sys.stdin))
