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

## La marque (ne pas confondre)

- **Vigie** = la marque commerciale : le produit, l'activité, et la **chaîne
  YouTube + réseaux sociaux** d'Anass. **C'est la marque qui figure sur le PDF**
  (logo Vigie + coordonnées).
- **Pavillon Noir** (`pavillon-noir.tech`) = le **blog** cybersécurité d'Anass
  (contenu / portfolio). À ne pas confondre avec la marque produit. C'est aussi
  le domaine qui sert de **terrain de test** (il appartient à Anass).

## Le ton du rapport

- **Direct et cash sur le constat** : on nomme le danger sans enrober.
- **Rassurant sur la solution** : « c'est réparable, voilà comment » → amène vers
  l'offre payante.

## Le parcours (le bouton)

- **Un seul bouton = tout d'un coup** : scan → rapport prêt (pas d'étapes à cliquer).
- **Arrêt obligatoire pour relecture** par Anass avant que le PDF parte au client
  (règle d'or + évite d'envoyer une fausse alerte à un prospect).
- **Saisie de départ (diag gratuit)** : le **domaine** + le **nom de la boîte**.
  Rien d'autre n'est requis (100 % public, aucun accord).
- Recherche sur une **personne** (pseudos du dirigeant…) : seulement si elle est
  cliente et a **signé** (règle n°3).

## La fin du PDF = outil de vente

- **Marque Vigie** en tête (logo + coordonnées pour recontacter).
- **Constat cash** au milieu, avec les **scénarios concrets** par trouvaille.
- **Appel à l'action** en bas vers l'offre de **sécurisation** payante
  (« ces failles, je te les corrige — appelle-moi »).
