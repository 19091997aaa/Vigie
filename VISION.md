# Vigie — vision produit (entretien avec Anass)

Décisions prises directement avec Anass, à lire avec `CLAUDE.md`.
Ce fichier grossit au fil des échanges — c'est la source de vérité sur
« ce qu'Anass veut comme résultat ».

## Le diagnostic gratuit : le livrable

- **Format : un PDF soigné** — un vrai document propre à remettre en main,
  pas un listing technique brut.
- Pour chaque trouvaille, le PDF donne un **scénario probable et concret** :
  « voici ce qu'un escroc pourrait faire avec ça ». Le risque est **raconté**,
  pas seulement listé. (Code existant : `vigie/scenarios.py`.)

## Qui pilote

- **Anass seul lance** le diagnostic depuis son Mac. Le client ne voit que le
  **PDF final**.
- Ouvrir un auto-diagnostic au client : **plus tard**, pas une priorité maintenant.

## Ordre des accroches dans le PDF (du plus choc au moins)

1. **Email usurpable** — on peut envoyer un faux mail au nom du patron (SPF/DMARC).
   C'est l'accroche n°1 : visuelle et parlante (montrer un faux mail à son nom).
2. **Fuites de mots de passe** — comptes des salariés présents dans des fuites.
3. **Données exposées** — infos publiques trouvables sur la boîte et ses gens.
4. **Sous-domaines / serveurs oubliés** — visibles et laissés à l'abandon.

## Critère pour garder un outil (le banc de comparaison)

Quand plusieurs outils tournent sur la même cible, on garde le meilleur selon,
**dans cet ordre de priorité** :
1. **Sortie claire** — facile à retranscrire en français simple (priorité n°1).
2. **Peu de faux positifs** — pas de bruit à trier.
3. **Plus de trouvailles** — remonte le plus d'infos réelles.
4. **Rapidité**.

(Code concerné : `vigie/banc.py`, `vigie/comparaison.py`.)
