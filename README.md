# php2shell-nse

**Rechercher les services web d'un périmètre, repérer les versions PHP concernées par PHP2Shell et afficher le correctif à appliquer.** Le script NSE couvre **CVE-2026-109618** et **CVE-2026-109619** à partir des versions annoncées dans les en-têtes HTTP.

## Lancer un contrôle

Prérequis : **Nmap et Git**. Aucun installateur ni bibliothèque Lua supplémentaire n'est nécessaire. Python 3 sert uniquement à l'export CSV optionnel.

```bash
git clone https://github.com/aehcktrn/php2shell-nse.git
cd php2shell-nse

nmap -sV -p- --script ./http-php2shell.nse application.example.com
```

Remplacez la cible par une IP ou un nom DNS, sans `https://`. **Vous n'avez pas à connaître le port web à l'avance** : `-p-` étend le scan aux ports TCP 1 à 65535 et `-sV` recherche les services exposés. Le NSE intervient sur les services HTTP/HTTPS reconnus et les ports web usuels.

## Scanner une liste de domaines

Créez **`domaines.txt`**, avec **un nom DNS exact par ligne**. Les commentaires commencent par `#`. Vous pouvez copier le modèle fourni, puis remplacer ses noms d'exemple par ceux de votre périmètre :

```bash
cp domaines.example.txt domaines.txt
```

Format attendu :

```text
# Applications a controler
application.example.com
portail.example.com
api.example.org
```

Utilisez les noms complets, sans `https://`, port, chemin, joker `*` ou suffixe CIDR. Un nom racine comme `example.com` n'inclut pas automatiquement ses sous-domaines : ajoutez chaque application souhaitée. La liste est fournie par l'opérateur ; sa propriété n'est pas vérifiée automatiquement.

Lancez le scan depuis un poste ayant accès aux applications :

```bash
mkdir -p results
nmap -sT -sV -Pn -p- --resolve-all \
  --script ./http-php2shell.nse \
  --script-timeout 20s \
  --stats-every 30s \
  -iL domaines.txt \
  -oA results/php2shell
```

Pour ses cibles, Nmap résout les noms listés, recherche les ports et identifie les services. Le NSE utilise le nom de l'application pour **Host HTTP et SNI TLS**. La commande affiche la progression toutes les 30 secondes et conserve les résultats en texte et XML.

`--resolve-all` couvre toutes les adresses obtenues pour chaque nom dans la famille choisie. Évitez `--unique` : plusieurs noms partageant une IP doivent conserver des contrôles distincts. Le script ne découvre pas de sous-domaines supplémentaires, ne suit pas les redirections et ne déduit aucune plage réseau à partir des domaines.

**Le scan de ports vise les IP résolues ; Host/SNI sélectionnent l'application lors des échanges web.** Un reverse proxy, un répartiteur de charge ou un frontal mutualisé peut masquer plusieurs backends. Le résultat décrit ce qui est visible par ce frontal, sans constituer un inventaire des machines, conteneurs ou runtimes derrière lui. Une liste de domaines n'isole donc pas les sondes TCP par application.

La commande utilise IPv4. Pour IPv6, effectuez une exécution distincte avec `-6`. `-Pn` tente les adresses même sans réponse à la découverte initiale ; cela peut allonger le scan. `--script-timeout 20s` borne chaque exécution NSE, pas la durée totale. Un port sans résultat NSE reste à vérifier.

## Lire le verdict et agir

La sortie terminal est courte : verdict, version PHP, correction conseillée et vérification. Exemple pour une version PHP 8.3.35 annoncée :

```text
| http-php2shell:
|   VULNERABLE PROBABLE (selon la version annoncee)
|   PHP : 8.3.35
|   Correctif : PHP >= 8.3.36 dans sa branche, ou paquet fournisseur corrigeant les deux CVE.
|_  Verification : Apres mise a jour, redemarrer les workers web ou redeployer les conteneurs; verifier le runtime actif et les backports fournisseur.
```

| Verdict affiché | État structuré | Action |
|---|---|---|
| `VULNERABLE PROBABLE (selon la version annoncee)` | `POTENTIALLY_VULNERABLE` | Appliquer le correctif indiqué, ou vérifier que le fournisseur l'a déjà rétroporté. |
| `VERSION CORRIGEE ANNONCEE` | `PATCHED_VERSION_ADVERTISED` | Confirmer que cette version est effectivement exécutée par les instances web. |
| `INDETERMINE - A VERIFIER` | `UNKNOWN` | Vérifier le runtime côté serveur, le chemin interrogé et l'hôte virtuel. |

**La détection repose sur la version annoncée ; l'exploitabilité n'est pas testée.** Le champ `exploitability` reste `NOT_TESTED`. Une version masquée, contradictoire ou non reconnue ne permet pas de conclure. Si une preuve suspecte figure parmi des versions contradictoires, l'état reste `UNKNOWN`, mais la vérification est signalée comme prioritaire.

### Exporter un tableau CSV

À partir du XML conservé par la commande de scan :

```bash
python3 report.py results/php2shell.xml -o results/php2shell.csv
```

L'export contient les évaluations du NSE et des lignes de couverture. **Filtrez la colonne `row_type`** : `ASSESSMENT` correspond à un résultat NSE ; `COVERAGE` signale un port TCP ouvert sans évaluation, ou un hôte sans autre résultat. Cela comprend aussi des services non HTTP, comme SSH : `NOT_ASSESSED` ne signifie ni vulnérable ni corrigé.

Les évaluations conservent le verdict, les versions, les seuils de correction et les actions du XML. Les preuves détaillées restent dans le fichier XML. La colonne `priority` permet de traiter d'abord `PATCH_OR_VERIFY_BACKPORT` et `VERIFY_PRIORITY`, puis `VERIFY_RUNTIME` et `CONFIRM_RUNTIME`.

Un XML tronqué ou une exécution Nmap qui n'est pas terminée avec succès est refusé : un rapport existant n'est alors pas remplacé.

Le CSV reflète uniquement les enregistrements présents dans le XML. Il ne peut pas répertorier les cibles absentes de ce fichier, notamment après un échec de résolution DNS. Consultez aussi les messages d'erreur de Nmap et rapprochez les résultats de votre inventaire de départ.

### Alternative : inventaire d'IP et de réseaux

Pour un périmètre réseau connu, `-iL` accepte aussi un fichier `perimetre.txt` contenant des IP, des plages CIDR ou des noms DNS :

```text
192.0.2.10
198.51.100.0/24
application.example.com
```

Remplacez alors `-iL domaines.txt` par `-iL perimetre.txt` dans la commande précédente. **Sur de grandes plages peu occupées, `-Pn -p-` peut prendre beaucoup de temps** : découpez les réseaux en lots. Un inventaire d'IP seul ne découvre pas tous les hôtes virtuels ; conservez aussi les noms d'applications connus.

## Correctifs de référence

Matrice issue des avis PHP du **21 octobre 2026**, vérifiés le **22 octobre 2026** :

| Branche | Premier correctif officiel |
|---|---|
| PHP 8.2 | **8.2.35** |
| PHP 8.3 | **8.3.36** |
| PHP 8.4 | **8.4.27** |
| PHP 8.5 | **8.5.12** |
| PHP 8.6 en préversion | **8.6.0RC4** |

Ces seuils sont des **minima**, ou peuvent être remplacés par un paquet fournisseur corrigeant les deux CVE. Après la mise à jour, assurez-vous que les workers PHP et les instances applicatives utilisent effectivement les nouveaux binaires.

Les branches PHP 5, PHP 7, PHP 8.0 et PHP 8.1 sont signalées comme potentiellement vulnérables. Des backports fournisseur existent, ainsi que des correctifs source PHP minimaux pour 7.4, 8.0 et 8.1. Un suffixe de distribution est conservé en preuve ; il ne suffit pas à établir l'application d'un correctif.

Pour `8.6.0`, les préversions alpha, bêta et RC1 à RC3 précèdent le correctif ; RC4 et les RC ultérieures reconnues atteignent le seuil. Les versions stables de la branche 8.6 sont également comparées à ce seuil. Les builds `-dev`, suffixes non reconnus et branches non référencées restent `UNKNOWN`. La matrice est intégrée au script : elle n'est pas actualisée par un service externe pendant les scans.

## Options pour une application précise

```bash
nmap -sV -Pn -p 443 \
  --script ./http-php2shell.nse \
  --script-args 'http-php2shell.vhost=application.example.com,http-php2shell.path=/index.php,http-php2shell.timeout=5000' \
  192.0.2.10
```

| Argument | Défaut | Utilité |
|---|---|---|
| `http-php2shell.path` | `/` | Chemin applicatif local, jusqu'à 2 048 caractères. URL complète, `//`, espaces, caractères de contrôle, antislashs et fragments `#` refusés. |
| `http-php2shell.vhost` | Nom fourni à Nmap | Nom DNS pour **Host et SNI**, en conservant l'IP ciblée. Sans schéma, port ou chemin. |
| `http-php2shell.timeout` | `5000` | Délai des opérations réseau en millisecondes, entier de 1 à 60000. |

`http.host` est pris en compte en l'absence de `http-php2shell.vhost`, avec les mêmes contraintes. L'option spécifique est prioritaire. Sur un port autre que 80 ou 443, le port est ajouté à Host, pas au SNI.

## Couverture et limites

Le script lit les indications `PHP/...` des en-têtes **`X-Powered-By`** et **`Server`** avec une requête GET normale. Il n'envoie aucune charge d'exploitation. Le corps lu est limité à 64 Kio ; ni ce corps ni les cookies ne sont enregistrés dans les preuves. Les sondes `-sV` de Nmap s'ajoutent à cette requête.

Les **redirections ne sont pas suivies**. Choisissez explicitement leur destination applicative si nécessaire. Une erreur réseau, un filtrage ou une absence de version ne démontre pas l'absence de PHP.

La couverture dépend des cibles fournies, de la visibilité réseau et de l'identification des services. `-p-` ne garantit pas l'identification de chaque application : les exclusions de détection de services de Nmap restent applicables. Hôtes virtuels non inventoriés, versions masquées, frontaux et backends multiples nécessitent un complément d'inventaire. La version PHP en ligne de commande peut différer de celle du service web.

## Données structurées et tests

Le XML conserve `state`, `cves`, `versions`, `evidence`, `http_status`, `reason` et `notes`. Il ajoute `verdict`, `fixed_versions`, `remediation`, `verification`, `priority` et `potentially_vulnerable_evidence` pour faciliter le suivi des corrections.

Les tests utilisent des réponses simulées et des serveurs HTTP/HTTPS en boucle locale. Prérequis : Lua 5.4, Python 3, OpenSSL et Nmap.

```bash
lua5.4 tests/unit.lua
python3 tests/integration.py
python3 -m unittest discover -s tests -p 'test_report.py'
```

`NMAP` et `NMAP_DATADIR` permettent de choisir une installation spécifique de Nmap. Le workflow GitHub Actions exécute les tests sur Ubuntu 24.04.

## Sources et licence

- [PHP — avis de sécurité et versions](https://www.php.net/).
- [CVE-2026-109618 — avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
- [CVE-2026-109619 — avis PHP officiel](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
- [Nmap — sélection des cibles](https://nmap.org/book/man-target-specification.html), [sélection des ports](https://nmap.org/book/man-port-specification.html), [identification des services](https://nmap.org/book/man-version-detection.html), [découverte des hôtes](https://nmap.org/book/man-host-discovery.html) et [bibliothèque HTTP NSE](https://nmap.org/nsedoc/lib/http.html).

Le code original de ce dépôt est distribué sous [licence MIT](LICENSE). Nmap et ses bibliothèques conservent leurs propres licences.
