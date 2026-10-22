# php2shell-scanner

**Scanner PHP2Shell basé sur Nmap, avec un module NSE autonome.**

**Rechercher les services web d'un périmètre, repérer les versions PHP concernées par PHP2Shell et suivre les corrections.** Lanceur **0.5.0**, module NSE **0.3.3**, pour **CVE-2026-109618** et **CVE-2026-109619**.

Le NSE recherche des versions annoncées dans les réponses HTTP. Le lanceur ajoute les campagnes sur fichier, la découverte de sous-domaines, les imports de noms, le suivi de couverture, les rapports et les preuves de runtimes fournies par l'opérateur. Le parcours est indépendant de l'organisation et de l'hébergeur.

## Démarrage : un fichier, deux commandes

Prérequis : **Nmap, Python 3.10 ou ultérieur et Git**. Le lanceur utilise uniquement la bibliothèque standard Python. Le NSE fonctionne directement avec Nmap.

```bash
git clone https://github.com/aehcktrn/php2shell-scanner.git
cd php2shell-scanner
```

Créez **un seul fichier `domaines.txt`**, avec les domaines à contrôler, un par ligne :

```text
example.com
example.org
```

Remplacez ces domaines d'exemple par les vôtres. Utilisez des noms sans `https://`, port, chemin, joker ou CIDR. Les commentaires commencent par `#` ; les noms internationalisés sont normalisés en IDNA. Le fichier peut aussi contenir des noms plus précis, comme `application.example.com`.

**Scanner les noms du fichier :**

```bash
python3 scan.py domaines.txt
```

**Découvrir leurs sous-domaines et scanner l'ensemble :**

```bash
python3 scan.py domaines.txt --discover
```

**Reprendre simplement une campagne interrompue :**

```bash
python3 scan.py --resume results/<campagne>
```

Les fichiers d'état nécessaires sont créés automatiquement. Aucune base, aucun service externe et aucun fichier de configuration ne sont à préparer.

Le **profil rapide est activé par défaut** dans les deux cas. Il recherche les services HTTP/HTTPS sur les ports TCP **80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000 et 9443**. Nmap identifie les services ; le lanceur résout IPv4 et IPv6 et transmet le nom testé dans Host HTTP et SNI TLS. Pour couvrir les **65 535 ports TCP**, ajoutez `--profile complet`.

Les ports demandés sont affichés au lancement. **Trouver PHP sur le port 80 n'arrête pas les contrôles des autres ports** : chaque service dispose de son propre budget HTTP. Sur les ports du profil rapide, le NSE essaie aussi le contrôle HTTP lorsque Nmap n'a pas identifié le service ; un protocole non web positivement identifié ne déclenche pas ce repli.

### Avec `--discover`

Le même `domaines.txt` fournit les racines de découverte et le périmètre autorisé : chaque nom autorise ses descendants. Par exemple, `example.com` inclut `api.example.com` ; `application.example.com` limite la découverte à cette branche. Le lanceur interroge **crt.sh**, normalise et dédoublonne les noms retenus, puis scanne les domaines fournis et les sous-domaines découverts. Aucun compte, clé d'API ou paquet Python supplémentaire n'est nécessaire.

La découverte utilise les certificats publics et reste **non exhaustive** : des noms internes ou sans certificat public peuvent manquer. Les noms hors du périmètre sont écartés avant leur résolution DNS.

### Lire les résultats

Le dossier horodaté sous **`results/` est créé automatiquement** et son chemin est affiché dans le terminal. Le seul fichier à fournir pour ces deux commandes est `domaines.txt` ; les rapports, listes de sortie et fichiers techniques sont générés par l'outil.

| Sortie à consulter | Contenu |
|---|---|
| `report.csv` | Une ligne par cible : `cible`, `php`, `vulnerable`, `explication`. |
| `report.json` | La même synthèse, un objet par ligne. |
| `discovered.txt` | Avec `--discover` : liste distincte des noms découverts et retenus, un par ligne. |

`discovered.txt` conserve aussi une racine si elle apparaît dans les résultats de la source, ainsi que les noms retenus qui ne résolvent plus. `targets.txt` contient la liste complète des cibles retenues. Le fichier d'entrée reste inchangé.

Pour choisir vous-même le dossier de sortie, ajoutez `--output results/ma-campagne`. Ce dossier doit être nouveau ou vide.

## Rapports et actions

### Une cible, une ligne

Les rapports principaux contiennent exactement **quatre champs**, dans cet ordre :

| cible | php | vulnerable | explication |
|---|---|---|---|
| application.example.com | 8.3.35 | OUI | Ports évalués : 80,443. Version annoncée concernée ; appliquer le correctif PHP 8.3.36 ou un backport attesté. |
| portail.example.com | 8.3.36 | NON | Ports évalués : 443,8443. Version corrigée annoncée sur les services évalués. |
| api.example.org | INCONNUE | INDETERMINE | Ports évalués : 443. Version PHP masquée ; vérifier le runtime actif. |

Ces lignes illustrent le format. **`php` contient les versions observées**, séparées par ` | ` lorsqu'il y en a plusieurs, ou `INCONNUE` lorsqu'aucune version n'est disponible. Dans une campagne `scan.py`, chaque nom DNS retenu garde sa propre ligne, même s'il partage une IP avec une autre cible. Un export XML autonome reprend le vhost explicite ou l'identité de l'entrée Nmap, avec l'IP en l'absence de nom ; plusieurs alias d'une même entrée restent groupés, car ils ne prouvent pas des tests distincts de chaque vhost.

**L'explication liste les ports ayant une évaluation NSE**, même indéterminée, puis le motif du résultat. Les ports ouverts pertinents sans évaluation PHP sont signalés séparément. Lorsqu'une redirection quitte l'origine contrôlée et n'est donc pas suivie, sa destination expurgée est affichée avec la mention **HORS PÉRIMÈTRE DU CONTRÔLE — destination non évaluée**. Cette mention décrit la limite de l'évaluation HTTP courante : elle ne signifie pas nécessairement que le nom est absent du périmètre DNS autorisé ou d'une autre cible de la campagne. Les listes sont triées, dédoublonnées et bornées ; au-delà de dix ports, le nombre restant est indiqué. Les ports fermés ou filtrés ne figurent pas dans cette liste d'évaluations : leurs états restent dans les fichiers Nmap de `raw/`. Un port cité dans le motif de vulnérabilité désigne le service qui justifie le résultat, pas le seul port contrôlé.

- **`OUI`** : au moins un service annonce clairement une version concernée, sans preuve valide de correction, ou un inventaire atteste un runtime encore affecté. L'explication précise le correctif ou la preuve disponible. Une version annoncée ne démontre pas l'exploitabilité.
- **`NON`** : les services pertinents évalués annoncent des versions corrigées ou disposent d'attestations valides de correction, sans contrôle HTTP ou réseau manquant. Une redirection HTTP vers le même nom en HTTPS n'est couverte que si sa destination exacte — adresse, protocole, port, chemin et paramètres comparables — a été évaluée séparément. Une ancienne version avec un backport attesté peut donc apparaître en `NON`, avec la version conservée et l'attestation expliquée.
- **`INDETERMINE`** : version absente ou masquée, observations contradictoires, inventaire contradictoire ou contrôle incomplet. Une cause courte indique la vérification à effectuer ; l'absence de PHP identifié ne devient pas automatiquement `NON`.

Une version concernée clairement observée suffit à faire ressortir la cible en `OUI`, même si d'autres services restent indéterminés. Une observation suspecte au sein d'un parcours interrompu ou contradictoire reste `INDETERMINE`. Un service reconnu comme non web, par exemple SSH, ne dégrade pas à lui seul le résultat des services PHP évalués.

`report.csv` contient une ligne d'en-tête, puis une ligne physique par cible. `report.json` est une **liste JSON simple**, avec un objet de quatre champs par ligne, sans enveloppe technique ni observations imbriquées. Pour 465 cibles retenues, cela représente 465 résultats, soit 466 lignes CSV ou 467 lignes JSON avec les deux crochets. Les sous-domaines découverts ajoutent chacun leur propre résultat.

### Fichiers produits automatiquement

Tous les fichiers ci-dessous sont des sorties du scanner. Ils n'ont pas à être créés avant la première campagne.

| Fichier | Contenu |
|---|---|
| `manifest.json` | Périmètre, exclusions, empreintes des entrées, résolution A/AAAA, paramètres et état de chaque exécution. |
| `state/events.jsonl` | Journal incrémental de récupération, écrit à chaque transition sans réécrire tout le manifeste. |
| `progress.json` | Progression provisoire explicitement marquée ; elle publie les positifs établis, jamais de résultat négatif avant la consolidation finale. |
| `.campaign.lock` | Verrou local empêchant deux processus de modifier la même campagne. |
| `targets.txt` | Ensemble des noms retenus et normalisés : cibles exactes, racines, imports et découverte. |
| `discovery.json` | Si découverte automatique : journal par racine, source, provenance, limites, compteurs, rejets et motifs d'erreur ; inventaire toujours non exhaustif. |
| `discovered.txt` | Si découverte automatique : noms concrets CT retenus, y compris les racines présentes dans la source ; certains peuvent ne plus résoudre. |
| `report.csv` | Synthèse à quatre colonnes, une ligne par cible. |
| `report.json` | Même synthèse sous forme de liste JSON, un objet par ligne. |
| `changes.csv` | Comparaison avec `--previous` ; en-têtes seuls sans comparaison. |
| `raw/report-details.json` | Bilan technique complet : évaluations par service, observations, preuves, couverture et métadonnées de campagne. Nécessaire au recontrôle et à la comparaison des nouveaux rapports. |
| Autres fichiers de `raw/` | Résultats Nmap `.xml`, `.nmap`, `.gnmap` et journaux par couple nom/IP. |

Le bilan technique distingue **domaines retenus après validation et dédoublonnage, résolus, tentés et évalués**. Les candidats écartés restent dans `excluded_candidates` du manifeste et de `raw/report-details.json`. Les échecs DNS, délais expirés, interruptions, XML invalides et cibles absentes d'un XML restent visibles dans la ligne de leur cible. Par défaut, les adresses DNS non globales (privées, loopback, link-local, CGNAT, multicast ou réservées) sont consignées avec `NO_PUBLIC_ADDRESS` et ne sont jamais transmises à Nmap. `--allow-non-global` lève explicitement cette protection pour un laboratoire maîtrisé ; ne l'utilisez pas pour une campagne Internet. Les erreurs d'une source de découverte sont consignées dans `discovery.json` et dans le bilan technique ; elles ne créent pas de cible fictive ni de résultat PHP supplémentaire.

### Évaluation réseau détaillée

Les états suivants sont conservés dans `raw/report-details.json` et dans la sortie du NSE autonome. Le rapport principal les résume avec les preuves d'inventaire et la couverture de la cible.

| État | Lecture et action |
|---|---|
| `POTENTIALLY_VULNERABLE` | **VULNERABLE PROBABLE**, selon la version annoncée : appliquer le correctif ou établir le backport fournisseur. |
| `PATCHED_VERSION_ADVERTISED` | **VERSION CORRIGEE ANNONCEE** : confirmer les runtimes actifs et tous les backends. |
| `UNKNOWN` | **INDETERMINE — A VERIFIER** : suivre le motif et l'action associée. |
| `NOT_ASSESSED` | Aucun résultat NSE exploitable pour cette ligne de couverture. |

`row_type=ASSESSMENT` désigne une évaluation NSE ; `COVERAGE` une absence d'évaluation, parfois normale pour un service non web comme SSH. Les comptes ne sont pas des nombres de machines uniques. `exploitability` reste **`NOT_TESTED`**. Les en-têtes `Server` et `X-Powered-By` peuvent être masqués, modifiés ou émis par un intermédiaire.

### Motifs des indéterminés

| `reason_code` | Suite proposée |
|---|---|
| `PHP_VERSION_HIDDEN` | PHP annoncé sans version : examiner le runtime et le paquet. |
| `PHP_NOT_IDENTIFIED` | Vérifier le point d'entrée ou l'inventaire applicatif. |
| `AUTHENTICATION_REQUIRED` | Utiliser un accès de contrôle adapté ou l'inventaire authentifié. |
| `HTTP_ACCESS_DENIED` | Vérifier les règles d'accès. |
| `RATE_LIMITED` | Ralentir et recontrôler après le délai imposé. |
| `NO_HTTP_RESPONSE` | Vérifier réseau, TLS et disponibilité. |
| `REDIRECT_NOT_ASSESSED` | Destination affichée comme **HORS PÉRIMÈTRE DU CONTRÔLE** et non évaluée ; la contrôler séparément si elle appartient au périmètre autorisé. |
| `CONFLICTING_VERSIONS` | Vérifier les chemins et runtimes associés aux versions. |
| `UNRECOGNIZED_BUILD` | Identifier le build et ses correctifs fournisseur. |
| `REQUEST_BUDGET_EXHAUSTED` | Couverture HTTP partielle : ajuster budget ou chemins. |

Des motifs de campagne complètent ces résultats : `DNS_ERROR`, `DNS_FAMILY_ERROR`, `SCAN_TIMEOUT`, `SCAN_SKIPPED`, `INVALID_SCAN_XML`, etc. Dans le bilan technique, `next_action`, `remediation` et `verification` donnent les suites attendues. Une preuve suspecte est conservée lorsqu'une incohérence impose `UNKNOWN`.

### Comparaison

```bash
python3 scan.py domaines.txt \
  --previous results/campagne-initiale/report.json \
  --output results/campagne-suivante
```

**Conservez le dossier de campagne complet.** Pour un `report.json` compact, `--previous` charge automatiquement `raw/report-details.json` dans le même dossier et vérifie que les deux rapports correspondent. Un compagnon absent ou incohérent est refusé avant les accès réseau. Les anciens rapports JSON détaillés de schéma `1` restent acceptés directement, sans fichier compagnon. Cette règle vaut aussi pour le profil `recontrole`.

Les rapports compacts des versions 0.4.1 à 0.4.6 restent acceptés avec leur compagnon selon leur rendu historique exact, même lorsque les règles actuelles recalculent un verdict plus prudent. Les nouveaux rapports appliquent toujours les règles 0.5.0.

Les changements sont classés en `NEW`, `CHANGED`, `UNCHANGED` et `NO_LONGER_OBSERVED`, en conservant nom, IP, port et protocole. Un changement DNS peut apparaître comme un nouveau service et un ancien non observé. **La disparition d'un service ne prouve pas sa correction.** Les changements de périmètre, de ports ou de visibilité doivent être pris en compte.

### Simplifier un rapport déjà produit

Pour obtenir les quatre colonnes à partir d'un ancien rapport JSON, **sans relancer de scan** :

```bash
python3 report.py results/ancienne-campagne/report.json -o synthese.csv
```

La même commande accepte un nouveau rapport JSON compact ou un XML Nmap. La conversion d'un JSON compact vers CSV ne nécessite pas son fichier compagnon. Pour exporter l'ancien CSV technique à partir d'un XML ou d'un JSON détaillé, ajoutez `--detailed` :

```bash
python3 report.py results/campagne-initiale/raw/report-details.json \
  --detailed -o details.csv
```

## Options avancées — facultatives

<details>
<summary>Découverte : périmètre, limites et ancienne syntaxe</summary>

Les deux formes suivantes restent disponibles :

- `python3 scan.py domaines.txt --discover` : le fichier fourni sert aux cibles, aux racines de découverte et au périmètre implicite.
- `python3 scan.py --discover-subdomains roots.txt` : ancienne syntaxe, pour conserver des racines de découverte dans un fichier séparé. Ce fichier autorise aussi les racines et leurs descendants par défaut ; voir [roots.example.txt](roots.example.txt).

`--discover` exige le fichier positionnel et ne se combine pas avec `--discover-subdomains`. Les deux options sont incompatibles avec le profil `recontrole` ; utilisez une campagne normale avec `--previous` pour découvrir à nouveau et comparer les résultats.

La découverte accepte au maximum **1 000 racines**, chacune avec au moins deux labels DNS. Si `--scope scopes.txt` est fourni, chaque racine doit être couverte par ce périmètre explicite, qui filtre aussi les cibles exactes et les imports combinés. Toutes les entrées explicites sont validées avant les accès réseau.

Une exclusion exacte de `example.com` empêche le scan de ce nom mais laisse la découverte de ses enfants active. L'exclusion `*.example.com` supprime la requête de découverte pour cette racine, tout en laissant `example.com` scannable si ce nom n'est pas exclu séparément. Les racines situées dans une zone exclue ne sont pas interrogées.

### Préparer un plan et borner la découverte

```bash
python3 scan.py domaines.txt --discover --dry-run
```

Avec cette option, **`--dry-run` effectue les requêtes HTTPS vers crt.sh et la résolution DNS des cibles**, puis produit le plan ; il ne lance pas Nmap. Les racines interrogées sont transmises à crt.sh. La collecte de certificats ne contacte pas les applications découvertes ; le scan des services commence ensuite, en dehors du mode plan.

| Limite de découverte | Défaut | Réglage |
|---|---|---|
| Délai total d'une requête, résolution de la source et lecture incluses | 30 s | `--discovery-timeout`, de 1 à 120 |
| Budget de la session de découverte | Automatique : 8 s/racine, minimum 300 s, plafond 7 200 s | `--discovery-budget`, de 1 à 86 400, garde la priorité |
| Noms CT uniques par campagne, avant filtrage du périmètre et des exclusions | 10 000 | `--discovery-max-names`, de 1 à 100 000 |
| Nouvelles tentatives sur HTTP 502/503/504 | 2 | `--discovery-retries`, de 0 à 5 |
| Backoff initial entre tentatives | 5 s | `--discovery-backoff-seconds`, de 1 à 60 |
| Cooldown du cache réussi | 30 min | `--discovery-cache-ttl-minutes`, de 1 à 1 440 |
| Cache de secours maximal si crt.sh échoue | 24 h | `--discovery-cache-max-age-hours`, de 1 à 168 |
| Réponse par racine | 8 Mio | Limite fixe |

Le plafond effectif de noms CT est également limité aux places restantes parmi les **100 000 cibles maximum** de la campagne, racines, cibles exactes et imports compris. Sa valeur est enregistrée dans `limits.effective_max_names` de `discovery.json`.

Les racines sont traitées séquentiellement, sans redirection. Le budget automatique vaut ainsi **3 720 secondes pour 465 racines** et sa valeur maximale est affichée au lancement. Un résultat réussi récent est réutilisé pendant le cooldown pour ne pas solliciter inutilement crt.sh. Les erreurs transitoires HTTP 502/503/504 sont retentées avec un backoff exponentiel et légèrement aléatoire, dans le budget de la session. Si elles persistent, un cache réussi assez récent peut servir de secours ; `cache_mode`, `cache_age_seconds` et chaque tentative restent visibles dans `discovery.json`. `--refresh-discovery` force une nouvelle interrogation et désactive le repli sur cache. Les noms découverts ne déclenchent pas de nouvelles recherches de certificats. Les autres erreurs, limitations de débit, délais et plafonds atteints sont conservés dans `discovery.json` ; une campagne partielle sort avec le code `2`. Une interruption conserve le bilan disponible et sort avec `130`. La reprise ouvre une nouvelle fenêtre de temps et n'interroge que les racines non terminées.

### Lire les limites de l'inventaire

La découverte reste **non exhaustive**, y compris après une réponse réussie : chaque résultat porte `exhaustive: false`. Les noms internes ou sans certificat public et les hôtes seulement couverts par un certificat générique peuvent manquer. Un SAN `*.example.com` est enregistré comme certificat générique et ne devient pas un nom d'hôte inventé. Aucune recherche par dictionnaire n'est effectuée.

Les certificats historiques peuvent fournir des noms qui ne répondent plus au DNS : ils restent dans `discovered.txt` avant résolution, et `NO_DNS_ADDRESS` reste visible dans le bilan de couverture partielle. Une réponse vide ne démontre pas l'absence de sous-domaines. crt.sh applique aussi ses propres limites ; le lanceur signale les plafonds détectables et l'incertitude de troncature lorsqu'il manque les compteurs nécessaires. Voir l'[interface JSON décrite par le mainteneur](https://groups.google.com/g/crtsh/c/bybDhKDszkg) et l'[implémentation de crt.sh](https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc).

</details>

## Reprendre une campagne interrompue

L'état est enregistré au fil de l'eau dans un journal local, puis consolidé dans le manifeste. Pour reprendre une campagne :

```bash
python3 scan.py --resume results/20261022T223344Z-9bb9cdcf
```

La reprise garde le même identifiant, poursuit d'abord une découverte ou une résolution DNS inachevée, valide les XML des endpoints `COMPLETED`, les réutilise sans nouveau trafic et ne relance que les endpoints incomplets, en échec ou expirés. Une sortie absente, tronquée ou rattachée à une autre cible n'est jamais réutilisée comme succès. Les commandes enregistrées dans le manifeste ne sont jamais exécutées directement : Nmap et ses arguments sont reconstruits depuis les champs validés. Trois tentatives cumulées au maximum sont autorisées par couple nom/IP par défaut. Les adresses non globales restent exclues, sauf dérogation explicite de laboratoire avec `--allow-non-global`. Si un chemin avec paramètres a été expurgé, une nouvelle campagne avec le chemin complet est requise. Une campagne peut rester `PARTIAL` après reprise lorsque des noms ne résolvent pas ou qu'une lacune de couverture indépendante de Nmap subsiste.

La **reprise** poursuit la même campagne. Le profil **recontrole** crée au contraire une nouvelle campagne, résout de nouveau les noms et produit de nouvelles observations à comparer.

<details>
<summary>Importer des noms ou appliquer des exclusions</summary>

Les imports, exclusions et périmètres séparés servent à adapter une campagne à des besoins particuliers. Ils sont facultatifs pour le parcours à un fichier décrit ci-dessus.

Pour compléter la découverte avec un export DNS ou applicatif existant :

```bash
python3 scan.py domaines.txt --discover --discover-from export-dns.csv
```

Pour importer des noms sans interroger crt.sh, le même fichier de domaines peut fournir explicitement le périmètre :

```bash
python3 scan.py domaines.txt --scope domaines.txt --discover-from export-dns.csv
```

Ajoutez `--exclude exclusions.txt` si des noms doivent être écartés. Les modèles [scopes.example.txt](scopes.example.txt), [exclusions.example.txt](exclusions.example.txt) et [discovery.example.csv](discovery.example.csv) décrivent ces formats ; leur préparation n'est requise que pour les options correspondantes.

`--dry-run` valide les entrées, **résout les noms** et écrit le plan sans lancer Nmap. Avec `--discover` ou `--discover-subdomains`, il interroge aussi crt.sh et produit les fichiers de découverte. Sans découverte automatique, le plan ne fait aucune requête HTTP. Une campagne ultérieure réalise sa propre résolution.

Le fichier positionnel est facultatif si `--discover-from` ou l'ancienne option `--discover-subdomains` fournit les noms. Plusieurs options `--discover-from` peuvent être combinées.

### Règles de périmètre

| Entrée | Effet |
|---|---|
| `example.com` dans `domaines.txt` avec `--discover`, ou dans le fichier `--scope` | Autorise ce nom et ses sous-domaines. |
| `archive.example.com` dans `exclusions.txt` | Exclut ce nom exact. |
| `*.sandbox.example.com` dans `exclusions.txt` | Exclut les sous-domaines de cette zone, **pas** `sandbox.example.com` lui-même. |

Pour exclure une zone entière, ajoutez son nom exact et `*.zone`. Les noms hors périmètre, invalides, ambigus ou exclus restent dans le manifeste avec leur provenance et leur motif de rejet. La propriété des domaines est déclarée par l'opérateur ; le programme ne la vérifie pas.

### Formats d'import

`--discover-from` exige un périmètre, fourni par `--scope`, par le fichier positionnel avec `--discover`, ou par les racines de `--discover-subdomains`. Les imports sont des fichiers **locaux** :

- **TXT** : un nom DNS complet par ligne, commentaires `#`.
- **CSV/TSV** : colonne `hostname`, `fqdn`, `name`, `domain` ou `host`, avec virgule, point-virgule ou tabulation. Plusieurs colonnes de noms contradictoires rendent l'entrée ambiguë.
- **JSON** : liste de noms ou d'objets avec les mêmes champs, éventuellement placée dans une propriété `records` ou `targets`.

Si `type` ou `record_type` est fourni, seuls `A`, `AAAA` et `CNAME` sont retenus. Développez les noms relatifs et `@` d'un export de zone en noms complets avant l'import. Les valeurs d'adresses ou de destinations dans l'export ne remplacent pas la résolution DNS du nom retenu.

`--discover-from` lit uniquement les exports fournis et n'interroge pas lui-même de service de découverte sur Internet. Ni les imports ni les certificats publics ne constituent un inventaire des backends derrière un frontal.

</details>

<details>
<summary>Choisir les ports, les délais et le recontrôle</summary>

| Profil | Commande | Couverture |
|---|---|---|
| Rapide, par défaut | `python3 scan.py domaines.txt` | TCP 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000 et 9443. |
| Complet, sur demande | `python3 scan.py domaines.txt --profile complet` | TCP 1 à 65535. |
| Recontrôle | `python3 scan.py --profile recontrole --previous results/campagne-initiale/report.json` | Noms et ports à revoir dans le rapport précédent, avec nouvelle résolution DNS. |

Les alias `complete`, `quick` et `recheck` sont acceptés. `--ports 80,443,8000-8100` remplace les ports du profil. Le manifeste conserve la couverture demandée. Dans `raw/report-details.json`, `scan_ports` indique les ports effectivement demandés pour chaque couple nom/IP ; `campaign.ports` reste la sélection par défaut et peut différer des ports retenus lors d'un recontrôle.

Le recontrôle écarte les lignes avec `inventory_patch_status=PATCH_CONFIRMED`. Une version corrigée seulement **annoncée** reste à confirmer. Il reprend les ports connus ; sans port exploitable, les ports de la campagne précédente servent de repli. Il récupère les chemins des observations et des preuves, y compris ceux ayant annoncé une version suspecte. Si un ancien chemin contenait des paramètres expurgés, fournissez son URL locale complète avec `--path` ou `--paths-file` : sinon le recontrôle s'arrête avant tout accès réseau. Il n'invente pas les valeurs et ne rejoue pas simplement le chemin sans paramètres. Un fichier de cibles peut restreindre le recontrôle ; `--scope` et `--exclude` restent applicables.

| Réglage | Défaut | Option |
|---|---|---|
| Familles | IPv4 et IPv6 | `--families ipv4`, `ipv6` ou `both` |
| Processus Nmap simultanés | 4 | `--workers`, de 1 à 32 |
| Processus simultanés vers une même IP | 2 | `--workers-per-ip`, de 1 à 32 |
| Tentatives cumulées par couple nom/IP | 3 | `--max-attempts`, de 1 à 10 |
| Résolution DNS par nom | 15 s | `--dns-timeout` |
| Durée par processus Nmap | 900 s | `--target-timeout` |
| Délai des opérations HTTP | 5 000 ms | `--http-timeout` |
| Budget de parcours HTTP par service | 20 000 ms | `--http-budget` |
| GET par service | 5 au maximum | `--max-requests`, de 1 à 20 |
| Redirections par chemin | 2 au maximum | `--redirects`, de 0 à 5 |
| Observations par chemin | 1 | `--samples`, de 1 à 3 |

Le lanceur fixe également `--script-timeout` à **22 secondes par défaut** : budget HTTP plus deux secondes. Le budget HTTP limite le lancement des requêtes et leur délai réseau restant ; le délai NSE borne le script. Ces limites ne représentent pas la durée totale de la campagne. Un scan complet peut atteindre le délai de 900 secondes sur une cible filtrée ; celle-ci sera signalée comme incomplète.

`--max-rate` transmet un plafond de sondes à **chaque processus Nmap**, sans borner toutes les requêtes HTTP. L'absence d'enregistrement AAAA est normale pour un service IPv4 ; une erreur de résolution dans une famille demandée rend en revanche la couverture partielle, même si l'autre famille a été scannée. Si le délai DNS expire, les réponses déjà reçues pour une famille sont conservées.

</details>

<details>
<summary>Adapter les chemins et le parcours HTTP</summary>

Le parcours commence automatiquement sur `/`. Si aucune version exploitable n'a été trouvée sur les chemins demandés, il peut essayer `/index.php`. Pour préciser un autre point d'entrée :

```bash
python3 scan.py domaines.txt --path /app/
```

L'option facultative `--paths-file paths.txt` accepte des chemins supplémentaires, un par ligne ; voir [paths.example.txt](paths.example.txt). Ce fichier ajoute jusqu'à **10 chemins**, soit **11 au total**, avec un budget commun. Cette limite s'applique également aux chemins récupérés lors d'un recontrôle : un dépassement est refusé, sans troncature silencieuse. Les caractères Unicode des chemins fournis au lanceur sont encodés en UTF-8 `%XX` pour les requêtes HTTP. Les chemins explicitement demandés sont parcourus même si un premier chemin annonce une version. Ajustez `--max-requests` selon les chemins, redirections et échantillons ; une limite atteinte est signalée.

Les redirections sont suivies uniquement dans la **même origine** : même nom, protocole et port, IP toujours épinglée. HTTP vers HTTPS, un autre port ou un autre nom restent des destinations à contrôler séparément, même si elles figurent dans le périmètre autorisé.

HTTP **401, 403 et 429 arrêtent le parcours**. Un `403` ne permet pas à lui seul d'identifier un WAF. Si le parcours prévu est interrompu après une première version annoncée, cette preuve est conservée mais l'évaluation reste `UNKNOWN` lorsque les autres contrôles n'ont pas abouti. Pour rechercher des réponses variables :

```bash
python3 scan.py domaines.txt --samples 2 --max-requests 8
```

Les versions contradictoires sont conservées et signalées comme prioritaires. Des réponses identiques ne prouvent pas que tous les backends ont été contrôlés.

</details>

## Preuves de runtimes — facultatives

L'import relie des **attestations d'inventaire authentifié** aux services. Il ne collecte pas par SSH, ne se connecte pas aux serveurs et ne vérifie pas cryptographiquement les attestations. La fiabilité de la collecte et des références reste sous le contrôle de l'opérateur.

Utilisez [runtime-inventory.example.json](runtime-inventory.example.json) comme modèle, en remplaçant toutes les valeurs d'exemple, notamment la date et les références :

```bash
python3 scan.py domaines.txt --inventory runtime-inventory.json
```

Le document contient `schema_version: "1"` et une liste `records`. Chaque record identifie le service par `hostname`, `port` et `scheme` (`http` ou `https`), avec une `ip` facultative pour restreindre la correspondance. Il fournit :

- `authenticated: true`, `source`, `evidence_reference` et `observed_at` avec fuseau horaire.
- `covers_all_backends`, qui **atteste** la couverture complète ou partielle.
- Des `instances` avec `id` unique, `runtime`, `version`, un `package` ou `build_id`, et `active_runtime_verified: true`.
- Pour chaque instance, les deux CVE dans `cves`, avec les statuts `fixed`, `affected` ou `unknown`.

Le programme contrôle structure, rattachement au service, fraîcheur, instances et statuts déclarés. **Une sortie `php -v`, une bannière ou un paquet mis à jour sur disque ne suffisent pas à confirmer le runtime actif.** Les backports doivent être établis par la collecte, pas déduits d'un suffixe.

La fraîcheur maximale est de **24 heures**, réglable par `--inventory-max-age-hours`. Une date située plus de cinq minutes dans le futur n'est pas une preuve exploitable.

| `inventory_patch_status` | Signification |
|---|---|
| `PATCH_CONFIRMED` | Les deux correctifs sont attestés sur tous les runtimes actifs déclarés, avec couverture complète et preuve récente. |
| `PATCH_MISSING_CONFIRMED` | Au moins un runtime actif attesté reste affecté. |
| `PARTIAL` | La preuve ne permet pas de confirmer l'ensemble du service. |
| `STALE` | Preuve correspondante trop ancienne. |
| `CONFLICT` | Attestations correspondantes contradictoires. |
| `UNVERIFIED` | Éléments insuffisants pour valider l'attestation. |
| `NOT_PROVIDED` | Aucune attestation correspondante. |

Ces conclusions sont **fondées sur l'inventaire importé**. Les références de preuve ne sont ni ouvertes ni contrôlées automatiquement. Dans le bilan technique, les statuts réseau et inventaire restent séparés : une ancienne bannière peut coexister avec `PATCH_CONFIRMED` lorsqu'un backport est attesté. Le rapport compact tient compte de cette attestation pour son résultat, tout en conservant la version annoncée dans `php`. Confirmer les correctifs est distinct de démontrer l'exploitabilité.

## NSE autonome et export compatible

Sans lanceur Python :

```bash
nmap -sT -sV -Pn -p- \
  --script ./http-php2shell.nse \
  --script-timeout 22s \
  application.example.com
```

Le parcours Nmap sur fichier et l'export CSV restent disponibles :

```bash
mkdir -p results
nmap -sT -sV -Pn -p- --resolve-all \
  --script ./http-php2shell.nse \
  --script-timeout 22s \
  -iL domaines.txt \
  -oA results/php2shell
python3 report.py results/php2shell.xml -o results/php2shell.csv
```

Cette commande Nmap utilise IPv4 ; faites une exécution distincte avec `-6` pour IPv6. `--resolve-all` couvre les adresses de la famille choisie. Évitez `--unique` lorsque plusieurs noms partagent une IP. Les IP/CIDR restent utilisables avec Nmap directement ; `scan.py` attend des noms DNS.

`report.py` produit les quatre colonnes compactes par défaut ; `--detailed` conserve l'ancien export technique. Il refuse les XML tronqués ou sans fin de scan réussie. **Cet export autonome n'a pas de manifeste** : il ne retrouve pas les domaines absents du XML après un échec DNS. Utilisez `scan.py` pour le rapprochement complet.

### Arguments NSE

| Argument | Défaut | Fonction |
|---|---|---|
| `http-php2shell.path` | `/` | Premier chemin local. |
| `http-php2shell.paths` | Aucun | Tableau de dix chemins supplémentaires au maximum. |
| `http-php2shell.vhost` | Nom de la cible | Nom pour Host/SNI, IP conservée. |
| `http-php2shell.timeout` | `5000` | Délai des opérations HTTP, en ms. |
| `http-php2shell.budget` | `20000` | Budget de parcours, en ms ; conserver `--script-timeout`. |
| `http-php2shell.max_requests` | `5` | GET totaux, de 1 à 20. |
| `http-php2shell.redirects` | `2` | Redirections de même origine, de 0 à 5. |
| `http-php2shell.samples` | `1` | Observations par chemin, de 1 à 3. |
| `http.useragent` | Identité du scanner | User-Agent HTTP ; une chaîne vide désactive l'en-tête. |

Exemple avec IP et hôte virtuel :

```bash
nmap -sT -sV -Pn -p 443 \
  --script ./http-php2shell.nse \
  --script-timeout 22s \
  --script-args 'http-php2shell.vhost=application.example.com,http-php2shell.path=/index.php,http-php2shell.paths={"/app/"},http-php2shell.samples=2' \
  192.0.2.10
```

Les chemins locaux sont limités à 2 048 caractères ; URL complètes, `//`, espaces, contrôles, antislashs et fragments sont refusés. `http.host` est accepté si `http-php2shell.vhost` est absent. Sur un port non standard, le port est ajouté à Host, pas à SNI.

Le NSE utilise par défaut un User-Agent transparent propre à `php2shell-scanner`, au lieu de l'identité générique du moteur NSE que certains WAF bloquent systématiquement. L'argument Nmap standard `http.useragent` permet de fournir une identité opérateur différente sans simuler un navigateur.

## Correctifs de référence

Matrice issue des avis PHP du **21 octobre 2026**, vérifiés le **22 octobre 2026** :

| Branche | Premier correctif officiel |
|---|---|
| PHP 8.2 | **8.2.35** |
| PHP 8.3 | **8.3.36** |
| PHP 8.4 | **8.4.27** |
| PHP 8.5 | **8.5.12** |
| PHP 8.6 en préversion | **8.6.0RC4** |

Ce sont des minima de comparaison ; un paquet fournisseur peut corriger les deux CVE sous une autre version. Après mise à jour, vérifiez que les workers et instances exécutent les nouveaux binaires.

PHP 5, PHP 7, PHP 8.0 et PHP 8.1 sont signalés comme potentiellement vulnérables. Des backports fournisseur existent, ainsi que des correctifs source PHP minimaux pour 7.4, 8.0 et 8.1. Un suffixe de distribution ne prouve pas la correction.

Pour `8.6.0`, alpha, bêta et RC1 à RC3 précèdent le correctif ; RC4 et les RC ultérieures reconnues atteignent le seuil. Les versions stables de cette branche sont comparées au même seuil. Builds `-dev`, suffixes inconnus et branches non référencées restent `UNKNOWN`. La matrice est intégrée au NSE et n'est pas actualisée par un service externe pendant le scan.

## Couverture, données et codes de sortie

Le NSE fait des GET ordinaires, sans déclencher volontairement d'épuisement mémoire ou d'exécution de code. **Les sondes de ports et de services `-sV` de Nmap s'y ajoutent.** Ce trafic actif apparaît dans les journaux et interagit avec les services.

Le scan TCP vise les IP résolues. Host/SNI sélectionnent l'application lors des échanges web ; **une liste de domaines n'isole pas le scan TCP sur un frontal mutualisé**. Backends cachés, noms absents des entrées et des certificats publics, services non reconnus, caches, versions masquées et restrictions d'accès limitent les observations. Les exclusions de détection de services de Nmap restent applicables même avec tous les ports TCP.

Le corps lu est limité à 64 Kio et n'est pas utilisé comme preuve. Corps et cookies ne sont pas conservés par le NSE. Les valeurs de paramètres sont expurgées des chemins et redirections enregistrés et du manifeste. Les fichiers temporaires d'arguments sont supprimés à la fin du traitement, y compris en mode plan ; les entrées d'origine restent chez l'opérateur. Les CSV neutralisent les cellules pouvant être interprétées comme des formules.

| Sortie du lanceur | Sens |
|---|---|
| `0` | Campagne techniquement terminée, ou plan produit. **Ne signifie pas que les services sont corrigés.** |
| `2` | Entrée invalide, erreur ou couverture incomplète, y compris une découverte partielle ; consulter le manifeste, `discovery.json` et le rapport disponibles. |
| `130` | Interruption ; bilan partiel conservé lorsque possible. |

## Tests

Les tests couvrent notamment le parcours à un seul fichier, le profil rapide par défaut, la découverte et les rapports compacts. Ils utilisent des réponses simulées et des serveurs HTTP/HTTPS en boucle locale. Les tests de découverte ne dépendent pas du service crt.sh public. Prérequis de développement : **Lua 5.4, Python 3.10+, OpenSSL et Nmap**.

```bash
lua5.4 tests/unit.lua
python3 -m unittest discover -s tests -p 'test_report.py'
python3 -m unittest discover -s tests -p 'test_compact_report.py'
python3 -m unittest discover -s tests -p 'test_runtime_inventory.py'
python3 -m unittest discover -s tests -p 'test_campaign_report.py'
python3 -m unittest discover -s tests -p 'test_scan.py'
python3 -m unittest discover -s tests -p 'test_discovery.py'
python3 -m unittest discover -s tests -p 'test_discovery_campaign.py'
python3 -m unittest discover -s tests -p 'test_campaign_state.py'
python3 tests/integration.py
python3 tests/test_scan_integration.py
```

`NMAP` et `NMAP_DATADIR`, ou `--nmap` et `--nmap-datadir`, permettent de choisir l'installation. Les tests réels vérifient transport, parcours, couverture et rapports ; ils ne démontrent pas une détection exhaustive de tous les déploiements PHP. GitHub Actions exécute les lots sur Ubuntu 24.04.

### Charge hors réseau validée

`python3 tests/load_volume.py --durable-journal 10000 100000` mesure le planificateur, le vrai journal local synchronisé sur disque et la chaîne d'export avec des doubles réseau, sans DNS, crt.sh ni Nmap réel. Sur Apple M4, macOS arm64 et Python 3.15.0, la mesure du 23 octobre 2026 a donné :

| Cibles | Soumises non terminées max. | Actives max. | Ordonnancement + journal | Erreurs simulées | Journal durable | Pic ordonnanceur | Export | Relecture | Pic rapport | Lignes finales |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 000 | 8 | 8 | 1,886 s | 9 990 échecs, 10 délais | 20 000 événements, 7,81 Mio | 14,28 Mio | 1,632 s | 1,260 s | 18,51 Mio | 10 000 |
| 100 000 | 8 | 8 | 20,568 s | 99 900 échecs, 100 délais | 200 000 événements, 78,65 Mio | 138,77 Mio | 16,577 s | 12,820 s | 186,28 Mio | 100 000 |

Le volume journalisé croît linéairement à raison de deux transitions par tâche dans ce scénario ; les pics mémoire sont ceux suivis par `tracemalloc`. Un test concentrant 200 tâches sur la même IP confirme séparément les plafonds de 8 tâches globales et 2 par IP. Ces mesures portent sur les structures locales et la consolidation, pas sur un débit Internet ni sur la durée de vrais scans. Un test distinct génère et relit effectivement un compagnon détaillé supérieur à l'ancienne limite de 128 Mio. La mémoire reste proportionnelle au nombre de cibles, car le rapport final doit conserver une ligne et ses observations par cible ; 100 000 est la limite actuelle d'une campagne.

## Sources et licence

- [PHP — avis de sécurité et versions](https://www.php.net/).
- [CVE-2026-109618 — avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
- [CVE-2026-109619 — avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
- [Nmap — cibles](https://nmap.org/book/man-target-specification.html), [ports](https://nmap.org/book/man-port-specification.html), [services](https://nmap.org/book/man-version-detection.html), [découverte des hôtes](https://nmap.org/book/man-host-discovery.html) et [bibliothèque HTTP NSE](https://nmap.org/nsedoc/lib/http.html).
- [Changelog](CHANGELOG.md).

Le code original du dépôt est distribué sous [licence MIT](LICENSE). Nmap et ses bibliothèques conservent leurs propres licences.
