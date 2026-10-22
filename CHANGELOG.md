# Changelog

## 0.4.6 — 2026-10-23

- Les redirections quittant l'origine contrôlée affichent désormais leur destination expurgée dans les rapports principaux avec la mention **HORS PÉRIMÈTRE DU CONTRÔLE — destination non évaluée**.
- Le bilan technique expose aussi `redirect_destinations` et `redirect_evaluation_scope`; le NSE marque chaque observation concernée sans suivre ni résoudre la destination.
- Les rapports compacts 0.4.5 dépourvus de cette nouvelle mention restent acceptés pour la comparaison et le recontrôle.

Le lanceur passe à **0.4.6** et le NSE à **0.3.3**. Le périmètre réseau, les seuils PHP et les règles de décision des verdicts sont inchangés.

## 0.4.5 — 2026-10-23

- Exclusion systématique avant Nmap des adresses DNS non globales, avec conservation explicite des adresses rejetées et du motif `NO_PUBLIC_ADDRESS` dans les rapports de couverture.
- Cache de découverte crt.sh avec cooldown de 30 minutes, repli borné à 24 heures et traçabilité de l'âge et du mode d'utilisation.
- Deux nouvelles tentatives avec backoff exponentiel et jitter sur les erreurs transitoires HTTP 502/503/504 de crt.sh.
- Reprise de campagne avec `--resume` : validation et réutilisation des XML terminés, reconstruction sûre des commandes et relance des seuls endpoints incomplets.

Le lanceur passe à **0.4.5** ; le NSE reste en **0.3.2**. Les seuils PHP et les règles de décision des verdicts sont inchangés.

## 0.4.4 — 2026-10-23

### Compatibilité WAF et résolution DNS

- Le NSE envoie désormais un User-Agent transparent propre à `php2shell-scanner`, car certains load balancers et WAF refusent systématiquement l'identité générique `Nmap Scripting Engine` avant que la réponse applicative puisse être évaluée.
- L'argument Nmap standard `http.useragent` reste utilisable pour définir une identité opérateur différente ou désactiver l'en-tête avec une chaîne vide ; les valeurs contenant des contrôles sont refusées.
- Les adresses IPv4-mappées en IPv6 (`::ffff:x.x.x.x`) renvoyées par certains résolveurs ne sont plus traitées comme des adresses IPv6 distinctes, ce qui évite les scans et évaluations en double.
- Une redirection HTTP vers le même nom en HTTPS ne rend plus la synthèse indéterminée lorsque la destination a été évaluée séparément et de façon concluante sur la même adresse ; les redirections étrangères, les autres backends et les destinations indéterminées restent des lacunes.
- Régressions unitaires couvrant le User-Agent effectif, sa validation, le filtrage défensif des IPv4-mappées et la couverture des redirections inter-services.

Le lanceur passe à **0.4.4** et le NSE à **0.3.2**. Les seuils PHP, le périmètre réseau et les règles de décision des verdicts sont inchangés.

## 0.4.3 — 2026-10-22

### Visibilité et contrôle de plusieurs ports

- Le rapport compact liste les ports ayant une évaluation NSE et distingue les ports ouverts pertinents sans évaluation PHP. Les quatre colonnes et la ligne unique par cible restent inchangées.
- Correction de l'ambiguïté qui faisait apparaître uniquement le premier port concerné, souvent le 80, dans l'explication alors que d'autres services avaient été évalués.
- Affichage au lancement de la liste de ports TCP demandés ; le recontrôle indique sa sélection propre à chaque cible.
- Repli du NSE sur les dix ports du profil rapide lorsqu'un service reste inconnu ou seulement attribué par table. Les services non web positivement identifiés et les ports exclus par Nmap ne déclenchent pas ce nouveau repli.
- Compatibilité stricte avec les rapports compacts 0.4.1 et 0.4.2 pour la comparaison et le recontrôle, sans accepter de compagnon incohérent.
- Régressions couvrant plusieurs services HTTP/HTTPS sur une même cible, leurs versions distinctes et les règles de sélection des ports.

Le lanceur passe à **0.4.3** et le NSE à **0.3.1**. Les seuils PHP et les règles de décision des verdicts sont inchangés.

## 0.4.2 — 2026-10-22

### Démarrage simplifié

- Un seul fichier de domaines pour le parcours courant : `python3 scan.py domaines.txt`.
- Nouveau booléen `--discover` : réutilise le fichier positionnel comme racines de découverte et périmètre implicite, puis scanne les domaines fournis et les sous-domaines retenus.
- Le profil rapide, sur les dix ports web usuels du scanner, devient le défaut. Le profil complet reste accessible avec `--profile complet` ; `--ports` garde la priorité.
- Liste de découverte `discovered.txt`, rapports compacts et dossier de campagne générés automatiquement ; aucun fichier de configuration supplémentaire à préparer pour l'usage courant.
- Ancienne option `--discover-subdomains roots.txt` conservée, mutuellement exclusive avec `--discover`. Le recontrôle reste distinct de la découverte automatique.
- README organisé autour des deux commandes usuelles, avec les réglages supplémentaires présentés comme facultatifs.

La version du lanceur passe à **0.4.2**. Le NSE autonome reste en **0.3.0** ; le format des rapports compacts et les seuils PHP sont inchangés.

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
