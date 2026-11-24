# Sources des « Conséquences » du rapport

Les textes de `vigie/consequences.py` (onglet « Conséquences » de chaque constat) s'appuient
sur les sources ci-dessous. Vérifiées le 24/11/2026. Si une loi change, corriger ici ET dans
`vigie/consequences.py`.

## Textes de loi

| Ce qu'on dit | Texte | Lien |
|---|---|---|
| Obligation de protéger les données personnelles | RGPD, art. 32 | https://www.cnil.fr/fr/reglement-europeen-protection-donnees/chapitre4#Article32 |
| Prévenir la CNIL d'une fuite dans les 72 h | RGPD, art. 33 | https://www.cnil.fr/fr/reglement-europeen-protection-donnees/chapitre4#Article33 |
| Prévenir les personnes si le risque est élevé | RGPD, art. 34 | https://www.cnil.fr/fr/reglement-europeen-protection-donnees/chapitre4#Article34 |
| Plafond : 10 M€ ou 2 % du CA mondial pour un manque de sécurité | RGPD, art. 83.4 | https://www.cnil.fr/fr/reglement-europeen-protection-donnees/chapitre8#Article83 |
| Procédure simplifiée de la CNIL : 20 000 € au plus | Loi Informatique et Libertés, art. 22-1 | https://www.cnil.fr/fr/la-procedure-de-sanction-simplifiee |
| Défaut de sécurité des données = délit | Code pénal, art. 226-17 | Légifrance, « Code pénal, article 226-17 » |
| Responsabilité civile (client victime) | Code civil, art. 1240 | Légifrance, « Code civil, article 1240 » |
| Plainte sous 72 h pour être indemnisé d'une cyberattaque (loi LOPMI) | Code des assurances, art. L.12-10-1 | https://www.tresor.economie.gouv.fr/Institutionnel/Niveau2/Pages/39db1de3-1230-46a0-8e1b-d38a739e0885/files/9065d98f-099e-4eb4-9ba5-23b68cd50feb |
| Fausse déclaration à l'assureur : nullité (volontaire) / réduction (involontaire) | Code des assurances, art. L.113-8 et L.113-9 | Légifrance, « Code des assurances, articles L113-8 et L113-9 » |
| NIS2 : entreprises de 50 salariés ou 10 M€ de CA dans certains secteurs ; loi « Résilience » votée à l'Assemblée le 17/11/2026, pas encore en vigueur | Directive (UE) 2022/2555 | https://cyber.gouv.fr/la-directive-nis-2 |
| Accessibilité des sites marchands depuis le 28/06/2025, microentreprises de services dispensées | Directive (UE) 2019/882 | https://www.economie.gouv.fr/entreprises/accessibilite-numerique |
| Récupérer un domaine qui vous imite | Syreli (Afnic, .fr) / UDRP (.com) | https://www.afnic.fr/noms-de-domaine/resoudre-un-litige/ |

## Exemples réels (onglet « Exemple réel »)

| Constats | Cas | Source |
|---|---|---|
| Vieux chiffrement (TLS 1.0/1.1) | Amendes CNIL en 2024 contre des organismes dont le site gardait TLS 1.0/1.1 après mise en demeure | [CNIL, 12/03/2024](https://www.cnil.fr/fr/la-cnil-prononce-quinze-nouvelles-sanctions-dans-le-cadre-de-la-procedure-simplifiee-depuis-janvier) |
| Mots de passe faibles | Une douzaine d'organismes sanctionnés entre juin et octobre 2026 (mots de passe faibles, comptes partagés, SHA-1) | [CNIL, 17/11/2026](https://cnil.fr/fr/38-sanctions-simplifiees) |
| SPF / DMARC / domaines imitateurs / salariés non formés | Entreprise agroalimentaire du Finistère, 65 000 € perdus par faux mail du « patron » (2024) ; +29 % de faux ordres de virement en 2024 (Cybermalveillance.gouv.fr) | [Clubic, 04/05/2026](https://www.clubic.com/dossier-610123-l-arnaque-au-faux-fournisseur-une-fraude-qui-cible-les-pme-et-detourne-les-virements.html) |
| Sauvegarde / plan de reprise | Lise Charmel (Lyon) : rançongiciel en novembre 2019, 1 150 salariés bloqués, redressement judiciaire en février 2020 | [Le Monde Informatique, 04/03/2020](https://www.lemondeinformatique.fr/actualites/lire-lise-charmel-en-redressement-judiciaire-apres-un-ransomware-78321.html) |

Règle : un exemple n'entre dans le rapport que s'il est public, daté et sourcé. Jamais
de nom de particulier.
