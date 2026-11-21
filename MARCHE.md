# Vigie — marché, cible et cadre légal (synthèse des études)

Synthèse de 4 études de marché internes (20-21/11/2026), filtrée pour ne garder
que ce qui sert le produit. À lire avec `CLAUDE.md` et `VISION.md`.

> ⚠️ **Ce repo contient la stratégie commerciale de Vigie. Le garder privé.**

---

## 1. La cible

- **Cœur de cible : TPE/PME sans informaticien** — artisans, garages, commerces,
  cabinets, PME familiales. Elles ont des failles béantes et personne pour s'en
  occuper.
- Chiffres : 1 168 292 entreprises de 1 à 9 salariés en France ; 212 813 de 10 à
  49 (16 075 en PACA). **16 % des TPE-PME** n'ont **aucune** mesure de cybersécurité.
- La niche **sécurité privée** (sociétés de gardiennage 10-49 sal.) a été testée
  comme première cible : **à éviter comme cible unique** — elle est minuscule
  (23 en Vaucluse, 196 en PACA, 1 478 en France) et l'obligation Dracar/CNAPS du
  1er octobre 2026 est **administrative, pas informatique** (ça se vend comme de
  l'aide admin, pas de la cyber).

## 2. Le cadre légal du diagnostic gratuit (LE PLUS IMPORTANT)

Ce qui décide de ce que Vigie a le droit de faire **sur un prospect qui n'a rien
demandé**. Source : Code pénal art. 323-1 et suivants, 321-1 (recel), positions CNIL.

| Action sur un prospect à froid | Statut | Pourquoi |
| --- | --- | --- |
| Lire ses DNS publics (SPF, DMARC, MX) → email usurpable ? | **ZONE SÛRE** | Lecture d'infos publiées pour être lues, sans entrer dans un système |
| Chercher des domaines imitateurs (typosquatting) dans les registres publics | **ZONE SÛRE** | Données de registres publics |
| Lire ce que le site publie (certificat, en-têtes, redirections) | **ZONE SÛRE** | Public |
| Lui envoyer un mail B2B avec le résultat DNS | **SOUS CONDITIONS** | Message lié à son activité, origine des données indiquée, désinscription simple, de préférence vers une adresse générique (contact@) |
| Diagnostic fuites (HIBP) sur un domaine **qu'il a vérifié** | **APRÈS SON ACCORD** | Le prospect prouve qu'il contrôle le domaine et accepte la recherche |
| Scanner ses ports, tester des mots de passe, chercher des failles | **INTERDIT sans autorisation écrite** | Accès frauduleux (323-1 : 3 ans, 100 000 € ; 5 ans, 150 000 € avec dégâts) |
| Chercher les adresses de ses salariés dans des fuites / le dark web | **INTERDIT** | Données personnelles issues d'un délit : la CNIL interdit leur réutilisation, recel possible (321-1 : 5 ans, 375 000 €). HIBP n'ouvre pas la recherche par domaine sans vérification de propriété |
| Le démarcher en citant une fuite où figurent ses salariés | **INTERDIT** | Source illicite, pas d'intérêt légitime possible |

**Conséquence pour le produit :** le **diag gratuit à froid** = DNS/email usurpable
+ typosquatting + exposition publique du site. **Les fuites de mots de passe ne
sont PAS dans le gratuit à froid** — elles arrivent seulement **après accord** du
prospect et **vérification de son domaine**, donc dans l'offre payante.

Pourquoi l'email usurpable est l'accroche : seuls **~7 % des domaines .fr** bloquent
vraiment l'usurpation (DMARC présent sur 19,5 %, dont 62,7 % en simple surveillance
`p=none`). **Plus de 9 boîtes sur 10 sont donc usurpables** → le test touche presque
tout le monde. Et la **fraude au virement a coûté 485 M€ en France en 2025 (+37 %)**,
« dans la majorité des cas suite au piratage d'une messagerie » (Cybermalveillance).
C'est le scénario concret à raconter dans le PDF.

## 3. Modèle de prix (hypothèse testée, à valider sur le terrain)

- Diagnostic complet ~290 €, mise en sécurité ~600 €, **suivi ~110-190 €/mois**.
- Le récurrent (abonnement) est la priorité (voir VISION.md).
- **Concurrents (diagnostic) : 490 € à 4 400 €.** Le moins cher relevé = PaperMind
  490 € (≤ 5 postes). **PaperMind vend déjà presque la même offre** (diag + mise en
  sécurité + surveillance au mois) → se différencier (voir positionnement).
- Piège d'un prix fixe : à 290 € fixe, un client de 40 postes paie autant qu'un
  client de 5. Prévoir un **prix par tranche de postes**.
- Budget réel des clients : **77 % des TPE-PME dépensent moins de 2 000 €/an** en
  sécurité ; 64 % ne prévoient aucune hausse. L'offre doit rester sous ce plafond.

## 4. Les canaux pour les atteindre

- **Leur prestataire informatique d'abord** : 43 % des 1-9 sal. et 58 % des 10-49
  s'y tournent pour la cyber. → piste **sous-traitance** (tu fais le diag, l'info-
  géreur garde la maintenance).
- **Cybermalveillance.gouv.fr** (référencement prestataire, gratuit) : c'est là
  qu'arrivent les victimes (27 934 entités aidées en 2025). **Exige un SIRET** +
  RC Pro. Jusqu'à 2 mois d'instruction.
- **CSIRT Urgence Cyber Région Sud** (PACA) : oriente les victimes vers des presta-
  taires régionaux. Exige un SIRET. (Mais c'est aussi un concurrent : il vend un
  « diagnostic + suivi » dès 350 €/an.)
- **Mail à froid** : réponse médiane **1,54 %** en Europe (LinkedIn : ~4 %). Il
  faut beaucoup de volume. Répondre **vite** (87 % des demandes ont une réponse en
  moins d'1 h).
- Concurrent gratuit de l'État : **MonAideCyber** (entretien d'1 h 30, 7 000+ entités
  accompagnées). Vigie se distingue par la **vérification technique réelle** (Mon-
  AideCyber n'est qu'un questionnaire déclaratif, sans contrôle technique).

## 5. Le gratuit convertit-il ? (prudence)

**Aucune donnée indépendante** ne prouve que le diagnostic gratuit convertit. Les
seuls chiffres viennent de vendeurs : **1,5 à 10,6 %** des audits gratuits à froid
deviennent clients ; un PDF seul convertit 4-6 %, **avec une vidéo commentée 18-25 %**
(d'où l'intérêt d'une courte vidéo du rapport). À traiter comme des hypothèses, à
remplacer par les vrais chiffres d'Anass après 100 envois.

## 6. Risques à garder en tête

- **Juridique** : voir le cadre légal (§2). Ne jamais franchir la zone « interdit ».
- **Image** : de faux « audits cyber » servent déjà à des escroqueries et à de
  l'espionnage (alertes gendarmerie 2023, DGSI 2022). Vigie doit être
  irréprochable sur la forme (marque claire, pas de ton alarmiste mensonger, pas
  de fausse obligation légale brandie).
- **Économique** : budget client faible + concurrent public gratuit. D'où le choix
  du récurrent à petit ticket plutôt que du gros one-shot.
