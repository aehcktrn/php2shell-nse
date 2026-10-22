# php2shell-nse

**Rechercher les services web d'un périmètre, repérer les versions PHP concernées par PHP2Shell et suivre les corrections.** Version **0.3.0**, pour **CVE-2026-109618** et **CVE-2026-109619**.

Le NSE recherche des versions annoncées dans les réponses HTTP. Le lanceur ajoute les campagnes sur fichier, les imports de noms, le suivi de couverture, les rapports et les preuves de runtimes fournies par l'opérateur. Le parcours est indépendant de l'organisation et de l'hébergeur.

## Installation et première campagne

Prérequis : **Nmap, Python 3.10 ou ultérieur et Git**. Le lanceur utilise uniquement la bibliothèque standard Python. Le NSE reste autonome et ne demande aucune installation Lua supplémentaire pour fonctionner dans Nmap.

```bash
git clone https://github.com/aehcktrn/php2shell-nse.git
cd php2shell-nse
cp domaines.example.txt domaines.txt
```

Remplacez les exemples dans `domaines.txt` par les **noms DNS exacts** à contrôler, un par ligne :

```text
# Applications du périmètre
application.example.com
portail.example.com
api.example.org
```

Utilisez des noms sans `https://`, port, chemin, joker ou CIDR. Les noms internationalisés sont normalisés en IDNA. Les commentaires commencent par `#`. Tous les domaines d'exemple sont réservés à la documentation et doivent être remplacés.

```bash
python3 scan.py domaines.txt
```

**Le port web n'a pas à être connu.** Par défaut, le lanceur recherche les services sur les **65 535 ports TCP**, résout **IPv4 et IPv6**, conserve chaque couple nom/IP et évalue les services HTTP/HTTPS reconnus par Nmap. Il transmet le nom de l'application dans **Host HTTP et SNI TLS**, avec l'IP issue de la résolution initiale.

Les sorties sont enregistrées dans un dossier horodaté sous `results/`. Pour choisir le dossier :

```bash
python3 scan.py domaines.txt --output results/campagne-initiale
```

Le dossier doit être **nouveau ou vide** : les résultats précédents ne sont pas écrasés.

## Préparer le périmètre et importer des noms

`domaines.txt` contient des cibles exactes : inscrire `example.com` ne découvre pas automatiquement ses sous-domaines. Pour compléter les cibles à partir d'exports DNS ou applicatifs, préparez les domaines autorisés et les exclusions :

```bash
cp scopes.example.txt scopes.txt
cp exclusions.example.txt exclusions.txt
cp discovery.example.csv discovery.csv
```

Remplacez les exemples, puis préparez un plan :

```bash
python3 scan.py domaines.txt \
  --scope scopes.txt \
  --discover-from discovery.csv \
  --exclude exclusions.txt \
  --dry-run \
  --output results/plan
```

`--dry-run` valide les entrées, **résout les noms** et écrit `manifest.json` et `targets.txt`. Il ne lance pas Nmap et ne fait aucune requête HTTP. Une campagne ultérieure réalise sa propre résolution ; le plan décrit les adresses observées à l'instant de sa création.

Pour exécuter, reprenez les mêmes entrées sans `--dry-run`, avec un autre dossier :

```bash
python3 scan.py domaines.txt \
  --scope scopes.txt \
  --discover-from discovery.csv \
  --exclude exclusions.txt \
  --output results/campagne-complete
```

Le fichier de cibles est facultatif si `--discover-from` fournit les noms. Plusieurs options `--discover-from` peuvent être combinées.

### Règles de périmètre

| Entrée | Effet |
|---|---|
| `example.com` dans `scopes.txt` | Autorise ce nom et ses sous-domaines. |
| `archive.example.com` dans `exclusions.txt` | Exclut ce nom exact. |
| `*.sandbox.example.com` dans `exclusions.txt` | Exclut les sous-domaines de cette zone, **pas** `sandbox.example.com` lui-même. |

Pour exclure une zone entière, ajoutez son nom exact et `*.zone`. Les noms hors périmètre, invalides, ambigus ou exclus restent dans le manifeste avec leur provenance et leur motif de rejet. La propriété des domaines est déclarée par l'opérateur ; le programme ne la vérifie pas.

### Formats d'import

`--discover-from` exige `--scope` et accepte des fichiers **locaux** :

- **TXT** : un nom DNS complet par ligne, commentaires `#`.
- **CSV/TSV** : colonne `hostname`, `fqdn`, `name`, `domain` ou `host`, avec virgule, point-virgule ou tabulation. Plusieurs colonnes de noms contradictoires rendent l'entrée ambiguë.
- **JSON** : liste de noms ou d'objets avec les mêmes champs, éventuellement placée dans une propriété `records` ou `targets`.

Si `type` ou `record_type` est fourni, seuls `A`, `AAAA` et `CNAME` sont retenus. Développez les noms relatifs et `@` d'un export de zone en noms complets avant l'import. Les valeurs d'adresses ou de destinations dans l'export ne remplacent pas la résolution DNS du nom retenu.

Exemple, également fourni dans [discovery.example.csv](discovery.example.csv) :

```csv
hostname,type,value
application.example.com,A,192.0.2.10
api.example.org,AAAA,2001:db8::10
portail.example.com,CNAME,front.example.com
```

Cette découverte repose sur les **exports fournis**. Elle n'interroge pas de service de découverte sur Internet et ne constitue pas un inventaire des backends derrière un frontal.

## Profils et limites

| Profil | Commande | Couverture |
|---|---|---|
| Complet, par défaut | `python3 scan.py domaines.txt --profile complet` | TCP 1 à 65535. |
| Rapide | `python3 scan.py domaines.txt --profile rapide` | TCP 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000 et 9443. |
| Recontrôle | `python3 scan.py --profile recontrole --previous results/campagne-initiale/report.json` | Noms et ports à revoir dans le rapport précédent, avec nouvelle résolution DNS. |

Les alias `complete`, `quick` et `recheck` sont acceptés. `--ports 80,443,8000-8100` remplace les ports du profil. Le manifeste conserve la couverture demandée. Dans les rapports, `scan_ports` indique les ports effectivement demandés pour chaque couple nom/IP ; `campaign.ports` reste la sélection par défaut et peut différer des ports retenus lors d'un recontrôle.

Le recontrôle écarte les lignes avec `inventory_patch_status=PATCH_CONFIRMED`. Une version corrigée seulement **annoncée** reste à confirmer. Il reprend les ports connus ; sans port exploitable, les ports de la campagne précédente servent de repli. Il récupère les chemins des observations et des preuves, y compris ceux ayant annoncé une version suspecte. Si un ancien chemin contenait des paramètres expurgés, fournissez son URL locale complète avec `--path` ou `--paths-file` : sinon le recontrôle s'arrête avant tout accès réseau. Il n'invente pas les valeurs et ne rejoue pas simplement le chemin sans paramètres. Un fichier de cibles peut restreindre le recontrôle ; `--scope` et `--exclude` restent applicables.

| Réglage | Défaut | Option |
|---|---|---|
| Familles | IPv4 et IPv6 | `--families ipv4`, `ipv6` ou `both` |
| Processus Nmap simultanés | 4 | `--workers`, de 1 à 32 |
| Résolution DNS par nom | 15 s | `--dns-timeout` |
| Durée par processus Nmap | 900 s | `--target-timeout` |
| Délai des opérations HTTP | 5 000 ms | `--http-timeout` |
| Budget de parcours HTTP par service | 20 000 ms | `--http-budget` |
| GET par service | 5 au maximum | `--max-requests`, de 1 à 20 |
| Redirections par chemin | 2 au maximum | `--redirects`, de 0 à 5 |
| Observations par chemin | 1 | `--samples`, de 1 à 3 |

Le lanceur fixe également `--script-timeout` à **22 secondes par défaut** : budget HTTP plus deux secondes. Le budget HTTP limite le lancement des requêtes et leur délai réseau restant ; le délai NSE borne le script. Ces limites ne représentent pas la durée totale de la campagne. Un scan complet peut atteindre le délai de 900 secondes sur une cible filtrée ; celle-ci sera signalée comme incomplète.

`--max-rate` transmet un plafond de sondes à **chaque processus Nmap**, sans borner toutes les requêtes HTTP. L'absence d'enregistrement AAAA est normale pour un service IPv4 ; une erreur de résolution dans une famille demandée rend en revanche la couverture partielle, même si l'autre famille a été scannée. Si le délai DNS expire, les réponses déjà reçues pour une famille sont conservées.

## Parcours HTTP

Le parcours commence sur `/`. Si aucune version exploitable n'a été trouvée sur les chemins demandés, il peut essayer `/index.php`. Ajoutez les chemins applicatifs utiles :

```bash
cp paths.example.txt paths.txt
python3 scan.py domaines.txt --paths-file paths.txt
```

`--path /app/` choisit le premier chemin. Le fichier ajoute jusqu'à **10 chemins**, soit **11 au total**, avec un budget commun. Cette limite s'applique également aux chemins récupérés lors d'un recontrôle : un dépassement est refusé, sans troncature silencieuse. Les caractères Unicode des chemins fournis au lanceur sont encodés en UTF-8 `%XX` pour les requêtes HTTP. Les chemins explicitement demandés sont parcourus même si un premier chemin annonce une version. Ajustez `--max-requests` selon les chemins, redirections et échantillons ; une limite atteinte est signalée.

Les redirections sont suivies uniquement dans la **même origine** : même nom, protocole et port, IP toujours épinglée. HTTP vers HTTPS, un autre port ou un autre nom restent des destinations à contrôler séparément, même si elles figurent dans le périmètre autorisé.

HTTP **401, 403 et 429 arrêtent le parcours**. Un `403` ne permet pas à lui seul d'identifier un WAF. Si le parcours prévu est interrompu après une première version annoncée, cette preuve est conservée mais l'évaluation reste `UNKNOWN` lorsque les autres contrôles n'ont pas abouti. Pour rechercher des réponses variables :

```bash
python3 scan.py domaines.txt --samples 2 --max-requests 8
```

Les versions contradictoires sont conservées et signalées comme prioritaires. Des réponses identiques ne prouvent pas que tous les backends ont été contrôlés.

## Rapports et actions

| Fichier | Contenu |
|---|---|
| `manifest.json` | Périmètre, exclusions, empreintes des entrées, résolution A/AAAA, paramètres et état de chaque exécution. |
| `targets.txt` | Noms retenus et normalisés. |
| `report.csv` | Évaluations, actions, preuves d'inventaire et absences de couverture. |
| `report.json` | Même bilan, avec observations et preuves détaillées. |
| `changes.csv` | Comparaison avec `--previous` ; en-têtes seuls sans comparaison. |
| `raw/` | Résultats Nmap `.xml`, `.nmap`, `.gnmap` et journaux par couple nom/IP. |

Le bilan distingue **domaines retenus après validation et dédoublonnage, résolus, tentés et évalués**. Les candidats écartés restent détaillés dans `excluded_candidates` du manifeste et du rapport JSON. Les échecs DNS, délais expirés, interruptions, XML invalides et cibles absentes d'un XML ne disparaissent pas du rapport.

### Évaluation réseau

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
| `REDIRECT_NOT_ASSESSED` | Contrôler explicitement la destination dans le périmètre. |
| `CONFLICTING_VERSIONS` | Vérifier les chemins et runtimes associés aux versions. |
| `UNRECOGNIZED_BUILD` | Identifier le build et ses correctifs fournisseur. |
| `REQUEST_BUDGET_EXHAUSTED` | Couverture HTTP partielle : ajuster budget ou chemins. |

Des motifs de campagne complètent ces résultats : `DNS_ERROR`, `DNS_FAMILY_ERROR`, `SCAN_TIMEOUT`, `SCAN_SKIPPED`, `INVALID_SCAN_XML`, etc. `next_action`, `remediation` et `verification` donnent les suites attendues. Une preuve suspecte est conservée lorsqu'une incohérence impose `UNKNOWN`.

### Comparaison

```bash
python3 scan.py domaines.txt \
  --previous results/campagne-initiale/report.json \
  --output results/campagne-suivante
```

Les changements sont classés en `NEW`, `CHANGED`, `UNCHANGED` et `NO_LONGER_OBSERVED`, en conservant nom, IP, port et protocole. Un changement DNS peut apparaître comme un nouveau service et un ancien non observé. **La disparition d'un service ne prouve pas sa correction.** Les changements de périmètre, de ports ou de visibilité doivent être pris en compte.

## Preuves de runtimes

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

Ces conclusions sont **fondées sur l'inventaire importé**. Les références de preuve ne sont ni ouvertes ni contrôlées automatiquement. Les statuts réseau et inventaire restent séparés : une ancienne bannière peut coexister avec `PATCH_CONFIRMED` lorsqu'un backport est attesté. Confirmer les correctifs est distinct de démontrer l'exploitabilité.

## NSE autonome et export compatible

Sans lanceur Python :

```bash
nmap -sT -sV -Pn -p- \
  --script ./http-php2shell.nse \
  --script-timeout 22s \
  application.example.com
```

Le parcours Nmap sur fichier et l'ancien export restent disponibles :

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

`report.py` refuse les XML tronqués ou sans fin de scan réussie. **Cet export autonome n'a pas de manifeste** : il ne retrouve pas les domaines absents du XML après un échec DNS. Utilisez `scan.py` pour le rapprochement complet.

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

Exemple avec IP et hôte virtuel :

```bash
nmap -sT -sV -Pn -p 443 \
  --script ./http-php2shell.nse \
  --script-timeout 22s \
  --script-args 'http-php2shell.vhost=application.example.com,http-php2shell.path=/index.php,http-php2shell.paths={"/app/"},http-php2shell.samples=2' \
  192.0.2.10
```

Les chemins locaux sont limités à 2 048 caractères ; URL complètes, `//`, espaces, contrôles, antislashs et fragments sont refusés. `http.host` est accepté si `http-php2shell.vhost` est absent. Sur un port non standard, le port est ajouté à Host, pas à SNI.

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

Le scan TCP vise les IP résolues. Host/SNI sélectionnent l'application lors des échanges web ; **une liste de domaines n'isole pas le scan TCP sur un frontal mutualisé**. Backends cachés, noms absents des exports, services non reconnus, caches, versions masquées et restrictions d'accès limitent les observations. Les exclusions de détection de services de Nmap restent applicables même avec tous les ports TCP.

Le corps lu est limité à 64 Kio et n'est pas utilisé comme preuve. Corps et cookies ne sont pas conservés par le NSE. Les valeurs de paramètres sont expurgées des chemins et redirections enregistrés et du manifeste. Les fichiers temporaires d'arguments sont supprimés à la fin du traitement, y compris en mode plan ; les entrées d'origine restent chez l'opérateur. Les CSV neutralisent les cellules pouvant être interprétées comme des formules.

| Sortie du lanceur | Sens |
|---|---|
| `0` | Campagne techniquement terminée, ou plan produit. **Ne signifie pas que les services sont corrigés.** |
| `2` | Entrée invalide, erreur ou couverture incomplète ; consulter le manifeste et le rapport disponible. |
| `130` | Interruption ; bilan partiel conservé lorsque possible. |

## Tests

Les tests utilisent des réponses simulées et des serveurs HTTP/HTTPS en boucle locale. Prérequis de développement : **Lua 5.4, Python 3.10+, OpenSSL et Nmap**.

```bash
lua5.4 tests/unit.lua
python3 -m unittest discover -s tests -p 'test_report.py'
python3 -m unittest discover -s tests -p 'test_runtime_inventory.py'
python3 -m unittest discover -s tests -p 'test_campaign_report.py'
python3 -m unittest discover -s tests -p 'test_scan.py'
python3 tests/integration.py
python3 tests/test_scan_integration.py
```

`NMAP` et `NMAP_DATADIR`, ou `--nmap` et `--nmap-datadir`, permettent de choisir l'installation. Les tests réels vérifient transport, parcours, couverture et rapports ; ils ne démontrent pas une détection exhaustive de tous les déploiements PHP. GitHub Actions exécute les lots sur Ubuntu 24.04.

## Sources et licence

- [PHP — avis de sécurité et versions](https://www.php.net/).
- [CVE-2026-109618 — avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
- [CVE-2026-109619 — avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
- [Nmap — cibles](https://nmap.org/book/man-target-specification.html), [ports](https://nmap.org/book/man-port-specification.html), [services](https://nmap.org/book/man-version-detection.html), [découverte des hôtes](https://nmap.org/book/man-host-discovery.html) et [bibliothèque HTTP NSE](https://nmap.org/nsedoc/lib/http.html).
- [Changelog](CHANGELOG.md).

Le code original du dépôt est distribué sous [licence MIT](LICENSE). Nmap et ses bibliothèques conservent leurs propres licences.
