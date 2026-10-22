# php2shell-nse

Script Nmap NSE pour rechercher une **version de PHP potentiellement concernée par PHP2Shell**, à partir des en-têtes HTTP exposés par une application.

Il couvre **CVE-2026-109618** et **CVE-2026-109619**. Il effectue une évaluation par version : il ne déclenche pas les vulnérabilités et ne confirme ni l'exploitabilité, ni une compromission. Une version masquée produit un résultat **`UNKNOWN`**, jamais une déclaration d'absence de vulnérabilité.

## Démarrage rapide

Prérequis : Nmap avec le moteur NSE et ses bibliothèques HTTP standard. Le script est autonome ; aucune bibliothèque Lua supplémentaire ni installation dans les répertoires de Nmap n'est nécessaire.

```bash
git clone https://github.com/aehcktrn/php2shell-nse.git
cd php2shell-nse

nmap -Pn -sV -p 80,443 \
  --script ./http-php2shell.nse \
  application.example.com
```

Indiquez le nom DNS de l'application, sans `https://`. Adaptez les ports au service. `-sV` aide Nmap à identifier HTTP et HTTPS ; les sondes de détection de service de Nmap s'ajoutent aux requêtes du script.

### IP connue, hôte virtuel et chemin applicatif

```bash
nmap -Pn -sV -p 443 \
  --script ./http-php2shell.nse \
  --script-args 'http-php2shell.vhost=application.example.com,http-php2shell.path=/index.php,http-php2shell.timeout=5000' \
  192.0.2.10
```

L'option `vhost` fixe le nom HTTP **Host** et le **SNI TLS**, tout en conservant l'IP ciblée pour la connexion. Elle permet d'interroger l'application voulue sur un serveur hébergeant plusieurs sites. Elle ne recherche pas les autres hôtes virtuels.

### Export des résultats

```bash
mkdir -p scan-results
nmap -Pn -sV -p 80,443,8080,8443 \
  --script ./http-php2shell.nse \
  -oA scan-results/php2shell \
  application.example.com
```

Le fichier XML contient les champs structurés du script. Le format texte reste directement lisible dans le terminal et le fichier `.nmap`.

## Interpréter les résultats

| `state` | Signification | Vérification à effectuer |
|---|---|---|
| `POTENTIALLY_VULNERABLE` | La version annoncée précède le correctif connu de sa branche, ou appartient à une ancienne branche concernée. | Vérifier le paquet effectivement exécuté, les éventuels correctifs rétroportés et la mise à jour des workers. |
| `PATCHED_VERSION_ADVERTISED` | La version annoncée atteint le seuil corrigé connu de sa branche. | Confirmer cette version sur les instances qui servent réellement l'application. |
| `UNKNOWN` | Les éléments disponibles ne permettent pas de conclure : version absente, ambiguë, non reconnue, contradictoire ou réponse inutilisable. | Contrôler côté serveur ou interroger le bon hôte virtuel et le bon chemin. |

Le champ **`exploitability` vaut toujours `NOT_TESTED`**. Une bannière est une déclaration du serveur, du proxy ou de l'application ; elle peut être obsolète ou modifiée. `PATCHED_VERSION_ADVERTISED` n'est donc pas une certification de correction.

Le rapport contient notamment :

- `cves` : les deux identifiants traités ;
- `versions` : les versions annoncées relevées ;
- `evidence` : la source de chaque version, son évaluation et le seuil de correction lorsqu'il est connu ;
- `http_status` : le statut HTTP reçu, lorsqu'il est disponible ;
- `reason` et `notes` : les motifs du résultat et les limites applicables.

Si les en-têtes annoncent des versions différentes, le résultat global reste `UNKNOWN` et les éléments sont conservés séparément. Une version suspecte dans ces éléments mérite une vérification, même lorsque l'ensemble est contradictoire.

## Versions de référence

Matrice établie à partir des avis officiels du **21 octobre 2026**, vérifiés le **22 octobre 2026** :

| Branche | Première version corrigée annoncée |
|---|---|
| PHP 8.2 | `8.2.35` |
| PHP 8.3 | `8.3.36` |
| PHP 8.4 | `8.4.27` |
| PHP 8.5 | `8.5.12` |
| PHP 8.6 en préversion | `8.6.0RC4` |

Le comparateur traite les composantes numériques, et non leur ordre alphabétique. Il distingue les préversions reconnues : pour `8.6.0`, les versions alpha, bêta et RC1 à RC3 précèdent le correctif ; RC4 et les RC ultérieures atteignent le seuil annoncé. Les versions stables de la branche 8.6 sont également comparées à ce seuil. Les builds `-dev`, suffixes non reconnus et branches futures non référencées restent `UNKNOWN`.

Les anciennes branches PHP 5, PHP 7, PHP 8.0 et PHP 8.1 sont signalées comme potentiellement vulnérables. Un suffixe de distribution est conservé dans la preuve, mais **ne démontre pas qu'un correctif a été rétroporté**. Inversement, une version de base ancienne peut être corrigée par son fournisseur. PHP a notamment publié des backports source minimaux pour 7.4, 8.0 et 8.1 ; les correctifs des distributions doivent être vérifiés auprès de leurs éditeurs.

La matrice est intégrée au script. Le scanner ne télécharge pas de données externes pendant une exécution : toute évolution de la matrice exige une mise à jour du dépôt.

## Arguments

| Argument | Défaut | Description |
|---|---|---|
| `http-php2shell.path` | `/` | Chemin local de l'application (2 048 caractères maximum). Il doit commencer par `/`. Une URL complète, `//`, les espaces, caractères de contrôle, antislashs et fragments `#` sont refusés. |
| `http-php2shell.vhost` | Nom fourni à Nmap | Nom DNS à utiliser pour Host et SNI. Ne pas ajouter de schéma, de port ou de chemin. |
| `http-php2shell.timeout` | `5000` | Délai des opérations réseau, en millisecondes, entier de 1 à 60000. Ce n'est pas une limite globale de durée du scan Nmap. |

Si l'argument générique Nmap `http.host` est fourni sans `http-php2shell.vhost`, il sert aussi de nom Host/SNI et doit respecter le même format de nom DNS sans port. L'option spécifique `http-php2shell.vhost` est prioritaire. Sur un port autre que 80 ou 443, le port est ajouté à l'en-tête Host, pas au SNI.

## Comportement et limites

Le script utilise une requête **GET** normale et analyse uniquement les indications `PHP/...` des en-têtes **`X-Powered-By`** et **`Server`**. Il ne recherche pas de webshell, n'envoie pas de commande système, ne provoque pas volontairement d'épuisement mémoire et ne soumet pas de formulaire multipart.

La lecture du corps est limitée à **64 Kio** ; ce corps ne sert pas à identifier la version et n'est pas inclus dans le rapport. Les cookies et les autres en-têtes ne sont pas reproduits dans les preuves.

Les redirections ne sont **pas suivies**, même vers le même domaine. Le statut de redirection reste visible : choisissez explicitement le service et le chemin finaux à analyser. Une réponse de connexion refusée, un blocage WAF ou un timeout ne prouvent aucune vulnérabilité.

Un frontal peut masquer PHP, afficher sa propre bannière ou répartir les requêtes entre plusieurs versions. Ce contrôle ponctuel ne recense pas tous les backends. Pour conclure, vérifiez chaque runtime web effectivement utilisé : PHP-FPM, module Apache, conteneur ou autre intégration. La version du seul exécutable PHP en ligne de commande peut être différente.

## Développement et tests

Les tests unitaires exercent le script avec des réponses HTTP simulées. Les tests d'intégration utilisent Nmap et des serveurs HTTP/HTTPS sur la boucle locale ; ils ne sondent aucun service Internet.

Prérequis supplémentaires : Lua 5.4, Python 3 et OpenSSL.

```bash
lua5.4 tests/unit.lua
python3 tests/integration.py
```

Les variables `NMAP` et `NMAP_DATADIR` permettent aux tests d'intégration d'utiliser une installation locale spécifique de Nmap. Le workflow GitHub Actions exécute les deux suites sur Ubuntu 24.04. Les résultats d'une exécution sont à consulter dans les journaux correspondants.

## Sources

- [PHP — avis de sécurité et versions du 21 octobre 2026](https://www.php.net/).
- [CVE-2026-109618 — RCE via OOM corruption, avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
- [CVE-2026-109619 — RCE via stale global state, avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
- [Nmap — bibliothèque HTTP du moteur NSE](https://nmap.org/nsedoc/lib/http.html).

## Licence

Le code original de ce dépôt est distribué sous [licence MIT](LICENSE). Nmap et ses bibliothèques conservent leurs propres licences.
