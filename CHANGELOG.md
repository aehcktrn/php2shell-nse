# Changelog

## 0.6.1 — 2026-10-23

- Distinction entre destination hors périmètre, destination non visitée et destination effectivement contrôlée mais non conclusive sur PHP. Les réponses HTTP `403`/`404` et l'absence de version ne deviennent plus des exclusions de périmètre.
- Conservation séparée des preuves de visite exacte et de la conclusion PHP, sans transformer une réponse HTTP seule en verdict non vulnérable. Corrélation toujours stricte sur les IP, protocoles, ports, chemins et paramètres.
- Confirmation du périmètre DNS à profondeur quelconque et préservation de la lecture des rapports historiques.

Le lanceur passe à **0.6.1** ; le NSE reste en **0.4.0**. Aucun nouveau scan n'est nécessaire pour régénérer les rapports d'une campagne conservée.

## 0.6.0 — 2026-10-23

- Planification par le lanceur des destinations exactes des redirections autorisées, en conservant Host/SNI, les adresses épinglées, les exclusions et les ports de campagne. L'identité d'URL distingue les queries expurgées ; les boucles et la limite de chaîne sont communes aux phases.
- Budgets HTTP cumulés par nom/IP/port/protocole et partagés entre contrôles obligatoires, redirections et enrichissements. Réservation persistée avant le travail, reprise sans remise à zéro et comptabilité conservatrice lorsque la consommation après interruption est inconnue.
- Enrichissement limité à deux liens de navigation de même origine lorsque les contrôles précédents n'ont publié aucune version, sans récursion, query, formulaire, action ni dictionnaire de chemins ; nombre de liens examinés et taille analysée bornés.
- Reconnaissance stricte de la version principale dans les diagnostics `phpinfo()` déjà accessibles. Les corps sont bornés après décodage et ne sont jamais conservés ; les versions d'extensions et mentions documentaires restent exclues.
- Fusion des phases en une évaluation par service, en préservant chaque échantillon, toutes les versions et les contradictions. La preuve d'un autre nom reste rattachée à ce nom ; une destination nécessaire non couverte empêche un faux verdict `NON`.
- Compteurs techniques par service pour les gains de version de base, de redirection et de liens, les diagnostics seuls, les GET, le temps, les conflits et les quotas épuisés ou incertains.
- Suppression en mémoire des empreintes brutes de découverte Nmap avant écriture, pour éviter qu'un corps de diagnostic ne soit conservé dans `servicefp` ou une sortie texte. Migration prudente des anciennes tentatives NSE dont le coût HTTP est inconnu.
- Conservation des deux commandes usuelles, des quatre champs compacts, des quatre vues arborescentes et du rendu historique des rapports jusqu'à 0.5.5. La source de la version publiée est précisée lorsque utile dans les nouveaux rapports.

Le lanceur passe à **0.6.0** et le NSE à **0.4.0**. Les seuils de correction et la signification des verdicts restent inchangés. Les validations utilisent uniquement des fixtures et des services locaux ; cette évolution ne publie pas de release et ne lance pas de scan public.

## 0.5.5 — 2026-10-23

- Priorité à la cause réelle d'un résultat non conclusif dans la synthèse : accès HTTPS refusé ou version non identifiée plutôt qu'une simple redirection déjà demandée dans la campagne.
- Regroupement des causes identiques par ports et nombre d'adresses dans l'arborescence, en conservant les motifs distincts et les destinations non évaluées.
- Conservation du rendu exact des rapports compacts 0.5.4 lors du chargement de leur fichier compagnon.
- Identification de la version de rendu courante dans le rapport régénéré après reprise, tout en conservant la version initiale du scan dans le manifeste.

Le lanceur passe à **0.5.5** ; le moteur réseau NSE reste en **0.3.4**, sans changement du parcours HTTP.

## 0.5.4 — 2026-10-23

- Libellés explicites `VULNERABLE` et `NON-VULNERABLE` dans l'arborescence à la place de `OUI` et `NON`.
- Échantillonnage borné des pages reliées par le HTML au sein de la même origine, avec priorité aux chemins PHP, sans dictionnaire de chemins, soumission de formulaire, lien externe ni paramètres de requête.
- Agrégation de la version PHP au niveau du service web : une version observée sur une page qualifie les autres pages demandées et atteintes sur la même origine, sans masquer un refus HTTP, un délai ou un parcours incomplet.
- Priorité au signal positif : une version affectée observée sur une page, un port ou un backend classe le domaine `VULNERABLE`, même si d'autres contrôles restent incomplets.
- Conservation de `INDETERMINE` lorsqu'une version ou une partie du parcours n'est pas observable depuis Internet, afin de ne pas transformer une absence de preuve en faux résultat non vulnérable.
- Rapport arborescent directement présentable en quatre vues : inventaire crt.sh retenu, hôtes PHP confirmés, éléments vulnérables avec endpoint/version de preuve, et résultats non conclusifs avec leur cause.
- Application des filtres de liens à chaque redirection du parcours découvert ; un refus ou une absence de réponse sur une page liée conserve son motif de couverture incomplète.

Le lanceur passe à **0.5.4** et le NSE à **0.3.4**. Les valeurs historiques `OUI` et `NON` des exports CSV/JSON restent inchangées pour préserver leur compatibilité machine.

## 0.5.3 — 2026-10-23

- Contrôle explicite de `/` et `/index.php` dans l'usage simple, même lorsqu'une version PHP est déjà annoncée sur la racine ; les redirections HTTP vers ces deux destinations peuvent ainsi être corrélées exactement avec leur évaluation HTTPS.
- Ajout d'une cause opérationnelle courte aux lignes `INDETERMINE` de `report-tree.txt` : refus HTTP, absence DNS, version non exposée, redirection non couverte ou autre lacune principale.
- Maintien du verdict prudent lorsque le serveur, le CDN ou le WAF ne publie aucune version : le scanner n'invente pas une version à partir d'un simple indice applicatif.

Le lanceur passe à **0.5.3** et le NSE reste en **0.3.3**. Les deux commandes usuelles restent inchangées.

## 0.5.2 — 2026-10-23

- Génération automatique de `report-tree.txt`, regroupant les résultats sous chaque domaine racine selon leur hiérarchie DNS.
- Affichage de la version PHP et du verdict sur chaque cible ; les branches intermédiaires absentes du scan sont explicitement marquées `[regroupement]`.
- Conservation inchangée des rapports plats CSV et JSON pour les traitements automatisés et les comparaisons.

Le lanceur passe à **0.5.2** et le NSE reste en **0.3.3**. Aucun nouvel argument n'est nécessaire.

## 0.5.1 — 2026-10-23

- Corrélation des redirections avec toutes les cibles de la campagne : une URL exacte déjà contrôlée sous un autre nom DNS n'est plus présentée comme hors périmètre.
- Les destinations évaluées séparément mais encore indéterminées restent `INDETERMINE`, sans produire de faux verdict rassurant.
- Conservation de la lecture stricte des rapports 0.5.0 selon leur restitution d'origine.

Le lanceur passe à **0.5.1** et le NSE reste en **0.3.3**. Les commandes usuelles et le format à quatre champs restent inchangés.

## 0.5.0 — 2026-10-23

- Correction des verdicts de redirection : une destination n'est couverte qu'avec une observation concluante du même nom, de la même IP, du protocole, du port et du chemin exacts ; les paramètres expurgés restent indéterminés.
- Conservation des preuves indépendantes sur une ligne de redirection, notamment `PATCH_MISSING_CONFIRMED`, les versions concernées et les conflits.
- Lecture stricte des rapports compacts historiques 0.4.1 à 0.4.6 selon leur rendu d'origine, sans réutiliser leurs anciennes règles pour les nouvelles synthèses.
- Journal local incrémental et durable `state/events.jsonl`, verrou exclusif de campagne et manifestes consolidés aux frontières de phase au lieu d'une réécriture complète après chaque endpoint.
- Files DNS et Nmap bornées, état `RUNNING` posé au démarrage réel, limite par IP de deux processus par défaut et progression provisoire sans résultat négatif prématuré.
- Reprise étendue à la découverte et au DNS inachevés, identité stable des tâches, validation du rattachement des XML et historique borné à trois tentatives par défaut.
- Budget de découverte automatique de 8 secondes par racine, avec minimum de 300 secondes, plafond de 7 200 secondes et nouvelle fenêtre lors d'une reprise.
- Écriture progressive des rapports JSON et relecture des rapports détaillés dépassant l'ancienne limite de 128 Mio.
- Charges locales validées à 10 000 et 100 000 cibles ; scénario d'interruption/reprise, verrouillage, cardinalité, concurrence et croissance linéaire du journal couverts par les tests.

Le lanceur passe à **0.5.0** et le NSE reste en **0.3.3**. Les deux commandes usuelles et le rapport principal à quatre champs sont inchangés.

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
