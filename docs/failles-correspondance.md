# Table des failles F01-F34 : comment Vigie la lit

Fichiers (copiés tels quels le 26/11/2026) : `vigie/donnees_failles/`
- `pavillon-noir-failles-consequences.json` : **la source que Vigie lit**.
- `pavillon-noir-failles-consequences.csv` et `pavillon-noir-cas-reels.csv` : la même table
  pour Excel (séparateur « ; »). Un test vérifie qu'ils disent la même chose que le JSON.

Code : `vigie/failles.py`. Affichage : onglet « Conséquences » de chaque constat, sous les
rubriques habituelles, bloc « Faille Fxx · nom · gravité ».

## Ce que le rapport affiche (et n'affiche jamais)

| Affiché au client | Jamais affiché |
|---|---|
| id, famille, gravité, nom_technique, ce_que_ca_veut_dire, les 3 conséquences, ce_que_ca_lui_apporte, action_corrective | phrase_telephone, place_dans_l_offre, statut |
| cas réels de fiabilité **forte** | cas « moyenne » et « a_verifier » |

- Case **C** (et « A/C ») : seulement si le rapport a une autorisation signée.
- **F01, F02, F34 (fuites)** : traitées comme C, même marquées « A » dans la table.
  Chercher un prospect dans des fuites est interdit à froid (CNIL, recel art. 321-1).
- **F33** (« à construire ») : jamais affichée.

## Correspondance codes Vigie → failles

| Code du constat Vigie | Faille |
|---|---|
| `spf` | F03 |
| `dmarc` (titre « absent ») | F04 |
| `dmarc` (titre « p=none » / « pas en blocage ») | F05 |
| `dkim` | F06 |
| `domaines_imitateurs` (avec serveur de mail) | F11 |
| `domaines_imitateurs` (sans) | F10 |
| `bibliotheques` | F16 |
| `certificat`, `certificat_www`, `https`, `https_<adresse>`, `technos_non_chiffre` | F17 |
| `moteurs_exposition` (port 3389 vu) | F19 |
| `moteurs_exposition` (port 445, 139, 5000, 5001 vu) | F20 |
| `assureur_mfa_distance` | F07 (C) |
| `assureur_maj_30j` | F24 (C) |
| `assureur_droits_admin` | F25 (C) |
| `assureur_mdp_complexes` | F26 (C) |
| `assureur_sauvegarde_testee` | F28 (C) |
| `assureur_continuite_testee` | F30 (C) |

Pas encore reliées (Vigie n'a pas de contrôle qui les voit) : F01, F02, F08, F09, F12,
F13, F14, F15, F18, F21, F22, F23, F27, F29, F31, F32, F33, F34.
Écartées exprès : `cms` (Vigie dit « sous WordPress », pas « obsolète »), `marque_*`
(un nom pris n'est pas encore un faux profil), DMARC en quarantaine (ni F04 ni F05).

Ajouter une correspondance = une ligne dans `failles.CORRESPONDANCE` (un test vérifie
que la faille existe et que le code Vigie a sa fiche de conséquences).
