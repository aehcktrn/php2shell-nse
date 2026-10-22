# Changelog

## 0.4.1 — 2026-10-22

### Rapports compacts

- `report.csv` et `report.json` contiennent désormais une ligne par cible DNS, en regroupant ses IP, ports et chemins, avec seulement quatre champs : `cible`, `php`, `vulnerable`, `explication`.
- Versions PHP observées toujours visibles, ou `INCONNUE`, et résultat `OUI`, `NON` ou `INDETERMINE` accompagné d'une explication courte sur une seule ligne.
- Prise en compte des attestations de correction, des runtimes affectés et des contrôles manquants dans la synthèse ; une version masquée ou une absence de contrôle ne devient pas un résultat négatif.
- JSON principal sous forme de liste simple, un objet par ligne. Le bilan détaillé reste disponible dans `raw/report-details.json` ; `changes.csv` conserve sa structure.
- Compatibilité de `--previous` et du profil `recontrole` avec les anciens JSON détaillés et les nouveaux rapports compacts. Ces derniers nécessitent leur fichier compagnon cohérent dans le dossier de campagne.
- Conversion hors ligne d'un XML ou d'un rapport JSON en CSV compact avec `report.py`, sans relancer de scan ; option `--detailed` pour conserver l'export CSV technique à partir des données détaillées.
- Tests de cardinalité sur 465 cibles, d'agrégation des services, de preuve de backport, de conversion et de compatibilité du recontrôle ; ajout de la suite dédiée aux rapports compacts dans la CI.

La version du lanceur passe à **0.4.1**. Le NSE autonome reste en **0.3.0** ; les seuils PHP et les codes de sortie du lanceur sont inchangés.

## 0.4.0 — 2026-10-22

### Découverte de sous-domaines

- Option `--discover-subdomains roots.txt` : collecte passive des noms de certificats publics via crt.sh, sans clé d'API ni dépendance Python supplémentaire.
- Racines utilisées comme périmètre implicite et ajoutées aux cibles ; combinaison avec cibles exactes, imports locaux, périmètre explicite et exclusions.
- Validation des entrées avant accès réseau et filtrage des candidats avant résolution DNS ; les zones entièrement exclues ne sont pas interrogées.
- Normalisation IDNA, dédoublonnage, conservation des noms historiques et suivi des certificats génériques sans inventer de noms d'hôtes.
- Requêtes séquentielles avec délai par requête, budget global, plafond de noms et limite de taille de réponse ; erreurs et plafonds visibles, sans nouvelle tentative automatique.
- Fichiers `discovery.json` et `discovered.txt` avec journal des requêtes, provenance, compteurs et limites. La réussite d'une source ne constitue jamais un inventaire exhaustif.
- Le mode plan peut interroger crt.sh et résoudre les noms, sans lancer Nmap ; les erreurs de découverte rendent la campagne partielle.
- Fichier de racines d'exemple, documentation et tests de découverte isolés du service public dans la CI.
- Les lignes de couverture d'une source de découverte ne deviennent pas des cibles réseau lors d'un recontrôle.
- Correction du passage d'un chemin HTTP unique : l'argument NSE de chemins supplémentaires est omis lorsqu'il est vide, pour éviter un rejet par Nmap.

La version du lanceur passe à **0.4.0**. Le NSE autonome reste en **0.3.0** : cette évolution ne modifie ni la détection ni les seuils de correction.

## 0.3.0 — 2026-10-22

### Parcours HTTP

- Repli vers `/index.php` et liste de chemins applicatifs supplémentaires.
- Redirections bornées dans la même origine, avec conservation de l'IP ciblée.
- Budgets communs de requêtes et de temps, échantillonnage optionnel et arrêt sur HTTP 401/403/429.
- Causes structurées et actions adaptées aux résultats indéterminés.
- Preuves attachées aux chemins, noms, IP, ports, Host, SNI et statuts observés.
- Conservation des versions contradictoires, sans assimiler un échantillon uniforme à une couverture de tous les backends.
- Expurgation des valeurs de paramètres dans les chemins et redirections enregistrés.

### Campagnes

- Lanceur `scan.py` utilisant uniquement la bibliothèque standard Python.
- Profils complet, rapide et recontrôle ; IPv4 et IPv6 ; processus et délais bornés.
- Imports locaux TXT, CSV, TSV et JSON, filtrés par domaines autorisés et exclusions.
- Plan sans Nmap avec résolution DNS et export des noms retenus.
- Manifeste reliant les cibles demandées, les adresses résolues et les exécutions.
- Conservation des erreurs DNS, des échecs de famille d'adresses et des évaluations manquantes.
- Dossiers de campagne distincts, suppression des fichiers temporaires d'arguments et conservation des bilans partiels.

### Rapports et inventaire

- Rapports CSV et JSON, observations détaillées et comparaison entre campagnes.
- Changements `NEW`, `CHANGED`, `UNCHANGED` et `NO_LONGER_OBSERVED` ; une disparition ne vaut pas correction.
- Import de preuves de runtimes authentifiés, avec rattachement au service, fraîcheur, statuts des deux CVE et couverture déclarée des backends.
- Statut d'inventaire séparé du réseau ; aucune collecte serveur ni vérification cryptographique de l'attestation par l'outil.
- Maintien de l'interface `report.py scan.xml -o rapport.csv`, des trois états réseau NSE et de `exploitability=NOT_TESTED`.
- Tests unitaires et tests réels HTTP/HTTPS et campagne sur boucle locale dans la CI.

## 0.2.0 — 2026-10-22

- Parcours sur fichiers de noms DNS exacts et alignement Host/SNI.
- Verdicts lisibles, seuils de correction et actions de vérification.
- Export XML vers CSV avec distinction entre évaluations et absences de couverture.
- Validation des XML terminés, protection des cellules CSV et tests de transport HTTP/HTTPS.
