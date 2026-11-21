"""L'autorisation écrite du client, préparée par Vigie, à imprimer et à signer.

Sans elle, un scan actif ou un test d'intrusion est un accès frauduleux (art. 323-1
du Code pénal). Vigie produit deux fichiers :
  - autorisation.html : le document à imprimer (ou enregistrer en PDF), à faire
    signer par une personne qui a le droit de décider pour la société ;
  - autorisation.json : les mêmes informations, lues par Vigie. Les outils manuels
    vérifient que la cible et la date du jour sont bien couvertes.

La version SIGNÉE (scan ou PDF) est ensuite donnée à Vigie : son empreinte est notée
dans chaque rapport et chaque lancement (voir autorisation.verifier).

    python3 -m vigie autorisation --societe "Pavillon Noir" --representant "Anass B." \
        --cible pavillon-noir.tech --debut 2026-12-01 --fin 2026-12-15
"""
import datetime
import html
import json
import os
import secrets

from .modeles import ControleImpossible

TESTS = {
    "ports": "Recherche des services ouverts sur internet (scan de ports)",
    "failles": "Recherche de failles connues sur ces services (scan de vulnérabilités)",
    "manuels": "Tests d'intrusion manuels, lancés un par un par le prestataire",
}


def creer(societe, representant, cibles, debut, fin, tests=("ports", "failles"),
          prestataire="", contact_urgence=""):
    """Le contenu de l'autorisation (dictionnaire), vérifié avant d'être écrit."""
    if not societe or not representant or not cibles:
        raise ValueError("Il faut la société, le signataire et au moins une cible.")
    jour_debut, jour_fin = datetime.date.fromisoformat(debut), datetime.date.fromisoformat(fin)
    if jour_fin < jour_debut:
        raise ValueError("La date de fin est avant la date de début.")
    inconnus = [t for t in tests if t not in TESTS]
    if inconnus:
        raise ValueError("Tests inconnus : " + ", ".join(inconnus))
    return {
        "numero": datetime.date.today().strftime("%Y%m%d") + "-" + secrets.token_hex(3),
        "societe": societe, "representant": representant,
        "prestataire": prestataire, "contact_urgence": contact_urgence,
        "cibles": [c.strip().lower() for c in cibles if c.strip()],
        "debut": jour_debut.isoformat(), "fin": jour_fin.isoformat(),
        "tests": list(tests),
    }


def _date(iso):
    return datetime.date.fromisoformat(iso).strftime("%d/%m/%Y")


def en_html(mandat):
    e = html.escape
    cibles = "".join(f"<li><b>{e(c)}</b></li>" for c in mandat["cibles"])
    tests = "".join(f"<li>{e(TESTS[t])}</li>" for t in mandat["tests"])
    vide = "........................................"
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Autorisation de tests de sécurité n° {e(mandat['numero'])}</title>
<style>
body {{ font-family: Georgia, serif; max-width: 760px; margin: 30px auto; padding: 0 24px;
       color: #1c2533; line-height: 1.5; font-size: 15px; }}
h1 {{ font-size: 22px; margin-bottom: 4px; }} h2 {{ font-size: 16px; margin-top: 26px; }}
.num {{ color: #5b6b82; font-size: 13px; }} .cadre {{ border: 1px solid #c9d2df; padding: 12px 16px; }}
.signatures {{ display: flex; gap: 30px; margin-top: 30px; }}
.signatures div {{ flex: 1; border-top: 1px solid #1c2533; padding-top: 8px; min-height: 110px; }}
@media print {{ body {{ margin: 0; }} }}
</style></head><body>
<h1>Autorisation de tests de sécurité informatique</h1>
<p class="num">Document n° {e(mandat['numero'])} — préparé avec Vigie</p>

<h2>1. Les parties</h2>
<p>La société <b>{e(mandat['societe'])}</b>, représentée par
<b>{e(mandat['representant'])}</b>, qui déclare avoir le pouvoir de décider pour les
systèmes informatiques listés ci-dessous (ci-après « le client »),</p>
<p>autorise <b>{e(mandat['prestataire'] or vide)}</b> (ci-après « le prestataire ») à
réaliser les tests décrits ci-dessous.</p>

<h2>2. Ce qui peut être testé (périmètre)</h2>
<div class="cadre"><ul>{cibles}</ul></div>
<p>Tout ce qui n'est pas dans cette liste est exclu. Si un système est hébergé chez un
tiers (hébergeur, prestataire, service en ligne), le client déclare avoir vérifié que
ce tiers autorise ces tests, ou en avoir obtenu l'accord écrit. Un hébergement
<b>partagé</b> avec d'autres clients ne peut pas être testé sans l'accord de l'hébergeur.</p>

<h2>3. Les tests autorisés</h2>
<ul>{tests}</ul>
<p>Le prestataire ne cherche pas à modifier, supprimer ou copier les données du client.
Il s'arrête et prévient le client dès qu'un test risque de perturber son activité.</p>

<h2>4. La période</h2>
<p>Du <b>{_date(mandat['debut'])}</b> au <b>{_date(mandat['fin'])}</b> inclus.
En dehors de cette période, aucun test n'est autorisé.</p>

<h2>5. Contact en cas d'incident</h2>
<p>Côté client : {e(mandat['contact_urgence'] or vide)}</p>

<h2>6. Confidentialité</h2>
<p>Le prestataire garde secret tout ce qu'il découvre. Les résultats ne sont remis
qu'au client, et effacés à la fin de la mission sauf accord contraire.</p>

<h2>7. Rappel de la loi</h2>
<p>Sans cette autorisation, accéder ou se maintenir frauduleusement dans un système
informatique est puni de 3 ans d'emprisonnement et de 100 000 € d'amende
(article 323-1 du Code pénal). Cette autorisation rend les tests légaux, dans les
seules limites écrites ci-dessus. Le client peut la retirer à tout moment, par écrit.</p>

<div class="signatures">
<div>Pour le client<br>Nom, fonction, date, « Bon pour accord », signature et cachet</div>
<div>Pour le prestataire<br>Nom, date, signature</div>
</div>
</body></html>
"""


def ecrire(mandat, dossier):
    os.makedirs(dossier, exist_ok=True)
    base = os.path.join(dossier, f"autorisation_{mandat['numero']}")
    with open(base + ".html", "w", encoding="utf-8") as fichier:
        fichier.write(en_html(mandat))
    with open(base + ".json", "w", encoding="utf-8") as fichier:
        json.dump(mandat, fichier, ensure_ascii=False, indent=2)
    return base + ".html", base + ".json"


def lire(chemin):
    try:
        with open(chemin, encoding="utf-8") as fichier:
            return json.load(fichier)
    except (OSError, json.JSONDecodeError):
        raise ControleImpossible(f"Fiche d'autorisation illisible : {chemin}")


def couvre(mandat, cible, test, jour=None):
    """Renvoie la raison du refus, ou "" si la cible, le test et la date sont couverts."""
    jour = jour or datetime.date.today()
    cible = cible.strip().lower()
    if cible not in mandat.get("cibles", []):
        return f"« {cible} » n'est pas dans le périmètre signé ({', '.join(mandat.get('cibles', []))})."
    if test not in mandat.get("tests", []):
        return f"Ce type de test n'est pas autorisé : {TESTS.get(test, test)}."
    if not (datetime.date.fromisoformat(mandat["debut"]) <= jour
            <= datetime.date.fromisoformat(mandat["fin"])):
        return (f"Hors de la période signée (du {_date(mandat['debut'])} "
                f"au {_date(mandat['fin'])}).")
    return ""
