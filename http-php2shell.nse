local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Assesses possible exposure to PHP2Shell (CVE-2026-109618 and CVE-2026-109619)
from PHP versions advertised in the Server and X-Powered-By HTTP headers.

This is a version-based assessment, not an exploit or a confirmation that the
running service is vulnerable, patched, or compromised. Vendor backports are
not verified. Missing, conflicting, or unrecognized versions produce UNKNOWN.

The script makes a bounded sequence of ordinary GET requests. It can try
/index.php when the entry path has no usable PHP version and follow redirects
within the same origin. It never submits multipart bodies, triggers memory
exhaustion, or executes code. HTTP and HTTPS use Nmap's HTTP library.

Use -sV -p- to discover HTTP/HTTPS on nonstandard TCP ports automatically.
Nmap performs port and service discovery; this script assesses the web services
that Nmap identifies. Normal output shows a short verdict and patch guidance;
XML output retains all evidence and assessment details for perimeter reports.

References (reviewed 2026-10-22):
https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
https://www.php.net/
]]

---
-- @usage
-- nmap -sV -p- --script ./http-php2shell.nse application.example.com
-- nmap -sT -sV -Pn -p- --resolve-all --script ./http-php2shell.nse -iL domaines.txt -oA php2shell
-- nmap -sV -Pn -p443 --script ./http-php2shell.nse \
--   --script-args 'http-php2shell.vhost=application.example.com,http-php2shell.path=/index.php' 192.0.2.10
--
-- @args http-php2shell.path Origin-relative request path (default: /).
-- @args http-php2shell.vhost DNS hostname to use for HTTP Host and TLS SNI.
--   The scanned destination IP is preserved. No scheme or port is accepted.
-- @args http-php2shell.timeout Socket timeout in milliseconds, 1..60000
--   (default: 5000). Use --script-timeout for a total script deadline.
-- @args http-php2shell.paths Array of additional local paths (at most 10).
-- @args http-php2shell.max_requests Total GET request limit, 1..20 (default: 5).
-- @args http-php2shell.budget Request scheduling budget in milliseconds,
--   1..60000 (default: 20000). Keep --script-timeout for a hard NSE deadline.
-- @args http-php2shell.redirects Same-origin redirect limit per path, 0..5
--   (default: 2). Other hosts, schemes and ports are never followed.
-- @args http-php2shell.samples Observations per supplied path, 1..3 (default: 1).
--
-- @output
-- | http-php2shell:
-- |   VULNERABLE PROBABLE (selon la version annoncee)
-- |   PHP : 8.3.35
-- |   Correctif : PHP >= 8.3.36 dans sa branche, ou paquet fournisseur corrigeant les deux CVE.
-- |_  Verification : Apres mise a jour, redemarrer les workers web ou redeployer les conteneurs; verifier le runtime actif et les backports fournisseur.

author = "aehcktrn"
license = "MIT; see https://github.com/aehcktrn/php2shell-nse/blob/main/LICENSE"
categories = {"discovery", "safe"}

portrule = shortport.http

local PREFIX = "http-php2shell"
local POTENTIAL = "POTENTIALLY_VULNERABLE"
local PATCHED = "PATCHED_VERSION_ADVERTISED"
local UNKNOWN = "UNKNOWN"
local FIXES = {[2] = 35, [3] = 36, [4] = 27, [5] = 12}
local MAX_HEADER_BYTES = 8192
local MAX_EVIDENCE = 32
-- RFC HTTP product-token characters. A fragment of Not-PHP or Not.PHP is
-- not a PHP product. Percent and hyphen are escaped for Lua character sets.
local PRODUCT_TOKEN = "[!#$%%&'*+%.%^_`|~%w%-]+"

local function output()
  local result = stdnse.output_table()
  result.state = UNKNOWN
  result.detection_method = "HTTP response headers (version-based)"
  result.exploitability = "NOT_TESTED"
  result.script_version = "0.3.0"
  result.schema_version = "1"
  result.advisory_date = "2026-10-21"
  result.cves = {"CVE-2026-109618", "CVE-2026-109619"}
  result.versions = {}
  result.evidence = {}
  result.observations = {}
  result.requests_made = 0
  result.budget_exhausted = false
  result.traversal_complete = false
  result.notes = {
    "Headers are untrusted and can be hidden, altered, cached, or supplied by a proxy.",
    "Vendor backports are not verified; check the package/build used by the running web workers."
  }
  result.reason = "No reliable PHP version evidence was obtained."
  result.reason_code = "PHP_NOT_IDENTIFIED"
  return result
end

local ACTIONS = {
  NO_HTTP_RESPONSE = "Verifier la connectivite, TLS et le service; relancer le controle si necessaire.",
  AUTHENTICATION_REQUIRED = "Utiliser un acces de controle adapte ou verifier le runtime depuis l'inventaire authentifie.",
  HTTP_ACCESS_DENIED = "Verifier les regles d'acces au service; le statut 403 seul n'identifie pas un WAF.",
  RATE_LIMITED = "Reduire la cadence de la campagne et relancer apres le delai impose par le service.",
  REDIRECT_NOT_ASSESSED = "Controler separement la destination si elle appartient au perimetre autorise.",
  REDIRECT_LIMIT_REACHED = "Verifier la chaine de redirections et choisir directement le chemin applicatif.",
  PHP_VERSION_HIDDEN = "Verifier le paquet et le build du PHP utilise par les workers web.",
  PHP_NOT_IDENTIFIED = "Verifier le point d'entree ou completer avec l'inventaire applicatif.",
  CONFLICTING_VERSIONS = "Verifier les chemins et runtimes associes a chaque version observee en priorite.",
  UNRECOGNIZED_BUILD = "Identifier le build et ses correctifs fournisseur depuis un inventaire authentifie.",
  REQUEST_BUDGET_EXHAUSTED = "Relancer les chemins non termines avec un budget adapte; la couverture est partielle.",
  EVIDENCE_LIMIT_REACHED = "Verifier directement le service: les en-tetes depassent les limites d'interpretation.",
  INVALID_ARGUMENT = "Corriger les arguments indiques avant de relancer le controle.",
  CLOCK_CHANGED = "Relancer le controle apres stabilisation de l'horloge du poste de scan.",
}

-- Keep the complete machine-readable assessment, but give operators a compact
-- verdict and a branch-specific action. In particular, a hidden version or a
-- failed request is never rendered as an all-clear. Conflicting evidence keeps
-- UNKNOWN while retaining an urgent review priority when any version is suspect.
local function finish(result)
  local fixed_seen, fixed_labels = {}, {}
  result.fixed_versions = {}
  result.potentially_vulnerable_evidence = false
  for _, evidence in ipairs(result.evidence) do
    if evidence.state == POTENTIAL then
      result.potentially_vulnerable_evidence = true
    end
    local fixed = evidence.fixed_version
    if fixed and not fixed_seen[fixed] then
      fixed_seen[fixed] = true
      table.insert(result.fixed_versions, fixed)
      table.insert(fixed_labels, "PHP >= " .. fixed)
    end
  end

  local fixed_text = table.concat(fixed_labels, "; ")
  local update_check = "Apres mise a jour, redemarrer les workers web ou redeployer les conteneurs; verifier le runtime actif et les backports fournisseur."

  if result.state == POTENTIAL then
    result.verdict = "VULNERABLE PROBABLE (selon la version annoncee)"
    result.priority = "PATCH_OR_VERIFY_BACKPORT"
    if #result.fixed_versions > 0 then
      result.remediation = fixed_text .. " dans sa branche, ou paquet fournisseur corrigeant les deux CVE."
    else
      result.remediation = "Migrer vers une branche PHP maintenue et corrigee, ou appliquer un paquet fournisseur corrigeant les deux CVE."
    end
    result.verification = update_check
  elseif result.state == PATCHED then
    result.verdict = "VERSION CORRIGEE ANNONCEE"
    result.priority = "CONFIRM_RUNTIME"
    result.remediation = "Seuil " .. fixed_text .. " atteint selon la version annoncee."
    result.verification = "Confirmer le paquet et la version reellement executes par chaque worker web et backend; une banniere seule ne certifie pas la correction."
  else
    result.verdict = "INDETERMINE - A VERIFIER"
    result.priority = result.potentially_vulnerable_evidence and "VERIFY_PRIORITY" or "VERIFY_RUNTIME"
    if result.potentially_vulnerable_evidence then
      result.remediation = "Une version suspecte figure dans les preuves; verifier et corriger les runtimes concernes en priorite."
      if #result.fixed_versions > 0 then
        result.remediation = result.remediation .. " Minima par branche : " .. fixed_text .. "."
      end
      result.verification = update_check
    else
      result.remediation = "Statut non determine; verifier le paquet PHP et le correctif fournisseur sur le runtime web."
      result.verification = "Controler l'acces HTTP, le bon hote virtuel/chemin et chaque backend; une version masquee ne prouve pas une correction."
    end
  end

  result.next_action = ACTIONS[result.reason_code] or result.verification
  if result.state == UNKNOWN and not result.potentially_vulnerable_evidence then
    result.verification = result.next_action
  end
  local lines = {
    result.verdict,
    "PHP : " .. (#result.versions > 0 and table.concat(result.versions, ", ") or "non determine"),
    "Correctif : " .. result.remediation,
    "Verification : " .. result.verification
  }
  if result.state == UNKNOWN then
    table.insert(lines, "Detail : " .. result.reason_code .. " - " .. (result.error or result.reason))
  end
  table.insert(lines, "Requetes : " .. result.requests_made .. "; motif : " .. result.reason_code)
  return result, "\n" .. table.concat(lines, "\n")
end

local function valid_package_suffix(suffix)
  if suffix == "" then return true end
  if not suffix:match("^[-+~][%w%.+~_-]+$") then return false end
  -- Accept recognizable package revision forms, not arbitrary prerelease
  -- labels disguised as distribution suffixes (e.g. -rc or +RC1).
  local revision = suffix:sub(2)
  if not (revision:match("^%d") or revision:match("^r%d")
      or revision:match("^deb%d") or revision:match("^ubuntu%d")) then
    return false
  end
  for _, marker in ipairs({"alpha", "beta", "rc", "preview", "pre", "snapshot", "dev"}) do
    if suffix:find("%f[%a]" .. marker) then return false end
  end
  return true
end

local function classify(token)
  if #token > 128 then
    return UNKNOWN, "Version token is too long to interpret."
  end
  local major, minor, patch, suffix = token:match("^(%d+)%.(%d+)%.(%d+)(.*)$")
  if not major or #major > 2 or #minor > 3 or #patch > 6 then
    return UNKNOWN, "A complete, recognized PHP version was not advertised."
  end
  for _, component in ipairs({major, minor, patch}) do
    if #component > 1 and component:sub(1, 1) == "0" then
      return UNKNOWN, "Noncanonical version components cannot be assessed."
    end
  end
  major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)
  suffix = suffix:lower()
  if suffix:find("dev", 1, true) then
    return UNKNOWN, "Development builds require package or source verification."
  end

  local stage, number, package_suffix
  for _, candidate in ipairs({"alpha", "beta", "rc"}) do
    number, package_suffix = suffix:match("^[-~]?" .. candidate .. "(%d+)(.*)$")
    if number then
      stage = candidate
      break
    end
  end
  if stage then
    if #number > 4 or not valid_package_suffix(package_suffix) then
      return UNKNOWN, "Unrecognized prerelease version suffix."
    end
    number = tonumber(number)
    if number < 1 then
      return UNKNOWN, "Unrecognized prerelease number."
    end
  elseif not valid_package_suffix(suffix) then
    return UNKNOWN, "Unrecognized version suffix; verify the running build."
  end

  if major == 8 and minor == 6 then
    local fixed = "8.6.0RC4"
    if not stage then
      return PATCHED, "The advertised stable version follows the 8.6.0RC4 fix.", fixed
    end
    if patch == 0 and (stage == "alpha" or stage == "beta" or number < 4) then
      return POTENTIAL, "The advertised prerelease predates the 8.6.0RC4 fix.", fixed
    end
    if patch == 0 and stage == "rc" and number >= 4 then
      return PATCHED, "The advertised prerelease includes the upstream fix by version.", fixed
    end
    return UNKNOWN, "This prerelease is outside the verified release mapping.", fixed
  end

  local fixed_patch = major == 8 and FIXES[minor] or nil
  if fixed_patch then
    local fixed = string.format("8.%d.%d", minor, fixed_patch)
    if patch < fixed_patch then
      return POTENTIAL, "The advertised version predates the upstream fix; verify vendor backports.", fixed
    end
    if stage then
      return UNKNOWN, "Prerelease patch inclusion is not established by this version mapping.", fixed
    end
    return PATCHED, "The advertised version meets the upstream fixed release; the runtime is unverified.", fixed
  end

  if major == 5 or major == 7 or (major == 8 and minor < 2) then
    return POTENTIAL, "Legacy PHP branch: no current upstream release fix; verify vendor/source backports."
  end
  return UNKNOWN, "This PHP branch is outside the verified release mapping."
end

local function valid_vhost(value)
  if type(value) ~= "string" or #value == 0 or #value > 253
      or value:find("[^%w%.%-]") then
    return nil
  end
  value = value:lower():gsub("%.$", "")
  if value == "" or value:sub(1, 1) == "." or value:find("..", 1, true) then
    return nil
  end
  for label in value:gmatch("[^%.]+") do
    if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-"
        or label:find("_") then
      return nil
    end
  end
  return value
end

local function valid_path(path)
  return type(path) == "string" and #path <= 2048 and path:sub(1, 1) == "/"
    and path:sub(1, 2) ~= "//" and not path:find("[%c%s#\\]")
end

local function parameters()
  local path = stdnse.get_script_args(PREFIX .. ".path")
  if path == nil then path = "/" end
  if not valid_path(path) then
    return nil, "Invalid path: use a local /path without spaces, controls, backslashes, or a fragment."
  end
  local args = {path = path, paths = {path}}
  for _, spec in ipairs({{"timeout", 5000, 1, 60000}, {"budget", 20000, 1, 60000},
      {"max_requests", 5, 1, 20}, {"redirects", 2, 0, 5}, {"samples", 1, 1, 3}}) do
    local value = stdnse.get_script_args(PREFIX .. "." .. spec[1])
    if value == nil then value = spec[2] end
    if type(value) ~= "string" and type(value) ~= "number" then
      return nil, "Invalid " .. spec[1] .. ": an integer is required."
    end
    value = tonumber(value)
    if not value or value % 1 ~= 0 or value < spec[3] or value > spec[4] then
      return nil, "Invalid " .. spec[1] .. ": expected an integer between " .. spec[3] .. " and " .. spec[4] .. "."
    end
    args[spec[1]] = value
  end
  local extra = stdnse.get_script_args(PREFIX .. ".paths")
  if extra ~= nil then
    if type(extra) ~= "table" or #extra > 10 then
      return nil, "Invalid paths: provide an array of at most 10 local paths."
    end
    local seen = {[path] = true}
    for key, item in pairs(extra) do
      if type(key) ~= "number" or key % 1 ~= 0 or key < 1 or key > #extra or not valid_path(item) then
        return nil, "Invalid paths: each array item must be a valid local /path."
      end
    end
    for _, item in ipairs(extra) do
      if not seen[item] then
        args.paths[#args.paths + 1] = item
        seen[item] = true
      end
    end
  end
  local vhost = stdnse.get_script_args(PREFIX .. ".vhost")
  -- Align the generic Host override with SNI too; explicit .vhost takes priority.
  if vhost == nil then vhost = stdnse.get_script_args("http.host") end
  if vhost ~= nil then
    vhost = valid_vhost(vhost)
    if not vhost then
      return nil, "Invalid vhost: expected a DNS hostname without a scheme, port, or path."
    end
  end
  args.vhost = vhost
  return args
end

local function extract(response, result)
  local seen_evidence, seen_versions = {}, {}
  local php_seen, evidence_limited = false, false
  local function inspect(source, value)
    if type(value) ~= "string" then return end
    if #value > MAX_HEADER_BYTES then
      evidence_limited = true
      value = value:sub(1, MAX_HEADER_BYTES)
    end
    for product in value:gmatch(PRODUCT_TOKEN) do
      if product:lower() == "php" then php_seen = true end
    end
    for product, token in value:gmatch("(" .. PRODUCT_TOKEN .. ")/([^%s,;%(%)]+)") do
      local key = source .. ":" .. token:lower()
      if product:lower() == "php" and not seen_evidence[key] then
        if #result.evidence >= MAX_EVIDENCE then
          evidence_limited = true
          break
        end
        seen_evidence[key] = true
        local state, reason, fixed = classify(token)
        local evidence = stdnse.output_table()
        evidence.source = source
        -- Only version tokens are retained, never complete response headers.
        evidence.version = token:sub(1, 128):gsub("[%c]", "?")
        evidence.state, evidence.reason = state, reason
        evidence.fixed_version = fixed
        table.insert(result.evidence, evidence)
        if not seen_versions[token:lower()] then
          seen_versions[token:lower()] = true
          table.insert(result.versions, evidence.version)
        end
      end
    end
  end

  -- Raw fields preserve duplicate headers. Also accept the normalized header
  -- table (Nmap's public API); identical observations are deduplicated.
  for _, line in ipairs(response.rawheader or {}) do
    if type(line) == "string" then
      local name, value = line:match("^([^:]+):%s*(.*)$")
      name = name and name:lower()
      if name == "server" or name == "x-powered-by" then inspect(name, value) end
    end
  end
  for _, name in ipairs({"server", "x-powered-by"}) do
    local value = (response.header or {})[name]
    if type(value) == "table" then
      for _, item in ipairs(value) do inspect(name, item) end
    else
      inspect(name, value)
    end
  end
  result.php_detected = php_seen and "YES" or "UNKNOWN"
  if evidence_limited then
    result.reason = "Header evidence exceeded interpretation limits; verify the service directly."
    result.reason_code = "EVIDENCE_LIMIT_REACHED"
  elseif #result.versions > 1 then
    result.reason = "Conflicting PHP versions were advertised; inspect each evidence item and web worker."
    result.reason_code = "CONFLICTING_VERSIONS"
  elseif #result.evidence > 0 then
    result.state = result.evidence[1].state
    result.reason = result.evidence[1].reason
    result.reason_code = result.state == POTENTIAL and "AFFECTED_VERSION_ADVERTISED"
      or (result.state == PATCHED and "FIXED_VERSION_ADVERTISED" or "UNRECOGNIZED_BUILD")
  elseif php_seen then
    result.reason = "PHP is advertised without a usable version; patch status is indeterminate."
    result.reason_code = "PHP_VERSION_HIDDEN"
  else
    result.reason = "No PHP version advertised in Server or X-Powered-By; PHP may still be present."
    result.reason_code = "PHP_NOT_IDENTIFIED"
  end
end

-- Query values can contain session tokens; keep only the path in reports.
local function public_path(path)
  return path:find("?", 1, true) and (path:match("^[^?]*") .. "?[redacted]") or path
end

local function initial_scheme(port)
  local version = port.version or {}
  local name = port.service or version.name or ""
  return (version.service_tunnel == "ssl" or name == "https" or name == "ssl/http"
    or port.number == 443) and "https" or "http"
end

local function normalized_path(path)
  local pathname, query = path:match("^([^?]*)(.*)$")
  local segments = {}
  for segment in pathname:gmatch("[^/]+") do
    if segment == ".." then table.remove(segments)
    elseif segment ~= "." then segments[#segments + 1] = segment end
  end
  local normalized = "/" .. table.concat(segments, "/")
  if pathname:sub(-1) == "/" and normalized ~= "/" then normalized = normalized .. "/" end
  return normalized .. query
end

-- Returns a local path only after checking scheme, hostname and port. The
-- scanned IP never changes, and this function never performs DNS resolution.
local function redirect_path(location, current_path, name, scheme, number)
  if type(location) ~= "string" or #location > 2048 or location:find("[%c%s\\]") then
    return nil, "Invalid or ambiguous redirect destination."
  end
  location = location:gsub("#.*$", "")
  if location == "" then return nil, "Empty or fragment-only redirect destination." end
  if location:sub(1, 2) == "//" then location = scheme .. ":" .. location end
  local target_scheme, authority, path = location:match("^(%a[%w+.-]*)://([^/?]+)(.*)$")
  if target_scheme then
    target_scheme = target_scheme:lower()
    if target_scheme ~= "http" and target_scheme ~= "https" then
      return nil, "Redirect uses an unsupported scheme."
    end
    local target_name, port_text
    if authority:sub(1, 1) == "[" then
      target_name, port_text = authority:match("^%[([%x:%.]+)%](:?%d*)$")
    else
      target_name, port_text = authority:match("^([%w%.%-]+)(:?%d*)$")
    end
    if not target_name or not port_text or (port_text ~= "" and not port_text:match("^:%d+$")) then
      return nil, "Redirect authority is invalid or contains credentials."
    end
    target_name = target_name:lower():gsub("%.$", "")
    local target_port = port_text ~= "" and tonumber(port_text:sub(2))
      or (target_scheme == "https" and 443 or 80)
    if target_port < 1 or target_port > 65535 then return nil, "Invalid redirect port." end
    if path == "" then path = "/" elseif path:sub(1, 1) == "?" then path = "/" .. path end
    local destination = target_scheme .. "://" .. authority .. public_path(path)
    if target_scheme ~= scheme or target_name ~= name:lower():gsub("%.$", "") or target_port ~= number then
      return nil, "Redirect leaves the current origin.", destination
    end
  elseif location:match("^%a[%w+.-]*:") then
    return nil, "Redirect uses an unsupported or ambiguous scheme."
  else
    if location:sub(1, 1) == "/" then path = location
    elseif location:sub(1, 1) == "?" then path = current_path:match("^[^?]*") .. location
    else path = (current_path:match("^[^?]*"):match("^(.*/)") or "/") .. location end
  end
  if not valid_path(path) then return nil, "Invalid redirect path." end
  return normalized_path(path), nil, public_path(path)
end

local function location_header(response)
  local values, seen = {}, {}
  local function add(value)
    if type(value) == "string" and not seen[value] then
      values[#values + 1], seen[value] = value, true
    end
  end
  for _, line in ipairs(response.rawheader or {}) do
    if type(line) == "string" then
      local name, value = line:match("^([^:]+):%s*(.*)$")
      if name and name:lower() == "location" then add(value) end
    end
  end
  local value = (response.header or {}).location
  if type(value) == "table" then for _, item in ipairs(value) do add(item) end else add(value) end
  if #values == 1 then return values[1] end
  return nil
end

local HTTP_REASONS = {
  [401] = {"AUTHENTICATION_REQUIRED", "The endpoint requires authentication."},
  [403] = {"HTTP_ACCESS_DENIED", "The endpoint refused access; the blocking component is not established."},
  [429] = {"RATE_LIMITED", "The endpoint rate-limited the request; traversal stopped."},
}

local CAUSE_PRIORITY = {
  RATE_LIMITED = 100, AUTHENTICATION_REQUIRED = 90, HTTP_ACCESS_DENIED = 90,
  NO_HTTP_RESPONSE = 80, REDIRECT_NOT_ASSESSED = 70, REDIRECT_LIMIT_REACHED = 70,
  UNRECOGNIZED_BUILD = 60, PHP_VERSION_HIDDEN = 50, PHP_NOT_IDENTIFIED = 10,
}

action = function(host, port)
  local result = output()
  local args, error_message = parameters()
  if not args then
    result.reason, result.error, result.reason_code = error_message, error_message, "INVALID_ARGUMENT"
    return finish(result)
  end

  local request_host = {}
  for key, value in pairs(host) do request_host[key] = value end
  local name = args.vhost or valid_vhost(host.targetname) or valid_vhost(host.name) or host.ip
  request_host.targetname = name
  local host_field = name:find(":", 1, true) and ("[" .. name .. "]") or name
  if port.number ~= 80 and port.number ~= 443 then host_field = host_field .. ":" .. port.number end
  local headers = {["Accept-Encoding"] = "identity", Host = host_field}
  result.vhost, result.http_host, result.path = name, host_field, public_path(args.path)
  result.ip, result.port, result.scheme = host.ip, port.number, initial_scheme(port)
  result.tls_sni = result.scheme == "https" and name ~= host.ip and name or ""
  local start, previous_clock = nmap.clock_ms(), nil
  local clock_changed, stopped, evidence_limited, actionable = false, false, false, false
  local stop_code, stop_reason, stop_unassessed
  local planned_visits, started_visits = #args.paths * args.samples, 0
  local seen_versions = {}
  local last_reason, last_code = result.reason, result.reason_code

  local function remaining()
    local now = nmap.clock_ms()
    if (previous_clock and now < previous_clock) or now < start then
      clock_changed = true
      return 0
    end
    previous_clock = now
    result.elapsed_ms = math.max(0, now - start)
    return args.budget - result.elapsed_ms
  end

  local function observe(path, sample)
    local left = remaining()
    if left <= 0 or result.requests_made >= args.max_requests then
      result.budget_exhausted = true
      return nil
    end
    local observation = stdnse.output_table()
    observation.path, observation.ip, observation.port = public_path(path), host.ip, port.number
    observation.vhost, observation.http_host = name, host_field
    observation.scheme, observation.tls_sni = result.scheme, result.tls_sni
    observation.sample = sample
    observation.state, observation.versions, observation.evidence = UNKNOWN, {}, {}
    observation.reason_code, observation.reason = "NO_HTTP_RESPONSE", "No complete HTTP response was received."
    result.requests_made = result.requests_made + 1
    observation.request_number = result.requests_made
    local response = http.get(request_host, port, path, {
      header = headers, timeout = math.max(1, math.min(args.timeout, left)),
      redirect_ok = false, bypass_cache = true, no_cache = true,
      max_body_size = 65536, truncated_ok = true,
    })
    if type(response) == "table" and tonumber(response.status) then
      observation.http_status = tonumber(response.status)
      if response.ssl ~= nil then observation.scheme = response.ssl and "https" or "http" end
      observation.tls_sni = observation.scheme == "https" and name ~= host.ip and name or ""
      result.scheme, result.tls_sni = observation.scheme, observation.tls_sni
      result.http_status = observation.http_status
      extract(response, observation)
      if HTTP_REASONS[observation.http_status] then
        observation.http_condition = HTTP_REASONS[observation.http_status][1]
        stop_code, stop_reason = table.unpack(HTTP_REASONS[observation.http_status])
        stop_unassessed = observation.state == UNKNOWN
        if observation.state == UNKNOWN and #observation.versions == 0 then
          observation.reason_code, observation.reason = table.unpack(HTTP_REASONS[observation.http_status])
        end
        stopped = true
      end
      if observation.http_status >= 400 then
        observation.intermediary_possible = true
      end
      if response.truncated then observation.body_truncated = true end
    else
      stopped = true
      stop_code, stop_reason, stop_unassessed = observation.reason_code, observation.reason, true
    end
    if observation.php_detected == "YES" then result.php_detected = "YES" end
    if observation.reason_code == "EVIDENCE_LIMIT_REACHED" then evidence_limited = true end
    local retained = {}
    for _, item in ipairs(observation.evidence) do
      if #result.evidence >= MAX_EVIDENCE then evidence_limited = true; break end
      item.path, item.ip, item.port = observation.path, host.ip, port.number
      item.scheme, item.vhost = observation.scheme, name
      item.http_host, item.tls_sni = host_field, observation.tls_sni
      item.http_status, item.request_number = observation.http_status, observation.request_number
      actionable = actionable or item.state == POTENTIAL or item.state == PATCHED
      retained[#retained + 1], result.evidence[#result.evidence + 1] = item, item
      if not seen_versions[item.version:lower()] then
        seen_versions[item.version:lower()] = true
        result.versions[#result.versions + 1] = item.version
      end
    end
    observation.evidence = retained
    result.observations[#result.observations + 1] = observation
    last_reason, last_code = observation.reason, observation.reason_code
    if remaining() <= 0 then result.budget_exhausted = true end
    return observation, response
  end

  local function visit(path, sample)
    started_visits = started_visits + 1
    local visited, redirects = {}, 0
    while not stopped do
      if visited[path] then
        last_code, last_reason = "REDIRECT_LIMIT_REACHED", "A redirect loop was detected."
        break
      end
      visited[path] = true
      local observation, response = observe(path, sample)
      if not observation then break end
      local status = observation.http_status
      if not status or status < 300 or status >= 400 or status == 304 then return path end
      local destination, why, safe_destination = redirect_path(location_header(response), path, name, observation.scheme, port.number)
      observation.redirect_to = safe_destination
      if not destination then
        observation.redirect_followed = false
        observation.redirect_reason = why
        if observation.state == UNKNOWN and #observation.versions == 0 then
          observation.reason_code, observation.reason = "REDIRECT_NOT_ASSESSED", why
        end
        last_code, last_reason = observation.reason_code, observation.reason
        return path
      end
      if redirects >= args.redirects or visited[destination] then
        observation.redirect_followed = false
        observation.redirect_reason = "Same-origin redirect limit or loop reached."
        last_code, last_reason = "REDIRECT_LIMIT_REACHED", observation.redirect_reason
        if observation.state == UNKNOWN and #observation.versions == 0 then
          observation.reason_code, observation.reason = last_code, last_reason
        end
        return path
      end
      if result.budget_exhausted or result.requests_made >= args.max_requests then
        result.budget_exhausted = true
        observation.redirect_followed = false
        return path
      end
      observation.redirect_followed = true
      redirects = redirects + 1
      path = destination
    end
    return path
  end

  local visited_paths = {}
  for _, path in ipairs(args.paths) do
    if stopped or result.budget_exhausted then break end
    visited_paths[path] = true
    local final_path = visit(path, 1)
    for sample = 2, args.samples do
      if stopped or result.budget_exhausted then break end
      visit(final_path, sample)
    end
  end
  if not stopped and not result.budget_exhausted and not actionable and not visited_paths["/index.php"] then
    planned_visits = planned_visits + args.samples
    local final_path = visit("/index.php", 1)
    for sample = 2, args.samples do
      if stopped or result.budget_exhausted then break end
      visit(final_path, sample)
    end
  end

  remaining()
  -- A version obtained before a denied/unreachable path must not hide that
  -- path, nor any remaining explicitly requested paths or repeated samples.
  -- A version-bearing denied response can remain an observation when it is
  -- the only requested visit; it cannot stand in for skipped visits.
  local interrupted = stopped and (stop_unassessed or started_visits < planned_visits)
  result.traversal_complete = not interrupted and not result.budget_exhausted and not clock_changed
  if interrupted then result.traversal_reason_code = stop_code end
  if result.budget_exhausted then result.traversal_reason_code = "REQUEST_BUDGET_EXHAUSTED" end
  if clock_changed then result.traversal_reason_code = "CLOCK_CHANGED" end
  result.php_detected = result.php_detected or "UNKNOWN"
  -- A silent fallback must not hide the useful explanation from the entry
  -- path (for example a redirect to an origin that was not assessed).
  local cause_priority = CAUSE_PRIORITY[last_code] or 0
  for _, observation in ipairs(result.observations) do
    local priority = CAUSE_PRIORITY[observation.reason_code] or 0
    if priority > cause_priority then
      cause_priority = priority
      last_code, last_reason = observation.reason_code, observation.reason
    end
  end
  result.reason, result.reason_code = last_reason, last_code
  if #result.versions > 1 then
    result.reason_code = "CONFLICTING_VERSIONS"
    result.reason = "Different PHP versions were observed; inspect each path and runtime."
  elseif evidence_limited then
    result.reason_code = "EVIDENCE_LIMIT_REACHED"
    result.reason = "Evidence exceeded interpretation limits; the assessment is incomplete."
  elseif clock_changed then
    result.reason_code, result.reason = "CLOCK_CHANGED", "The scan clock moved backwards; traversal stopped."
  elseif result.budget_exhausted then
    result.reason_code = "REQUEST_BUDGET_EXHAUSTED"
    result.reason = "The request or scheduling budget was exhausted; traversal is incomplete."
  elseif interrupted then
    result.reason_code = stop_code
    result.reason = stop_reason .. " A requested path or sample was not assessed; earlier version evidence is retained."
  elseif #result.evidence > 0 then
    result.state, result.reason = result.evidence[1].state, result.evidence[1].reason
    result.reason_code = result.state == POTENTIAL and "AFFECTED_VERSION_ADVERTISED"
      or (result.state == PATCHED and "FIXED_VERSION_ADVERTISED" or "UNRECOGNIZED_BUILD")
  elseif result.php_detected == "YES" and last_code == "PHP_NOT_IDENTIFIED" then
    result.reason_code = "PHP_VERSION_HIDDEN"
    result.reason = "PHP was advertised without a usable version."
  end
  if args.samples > 1 then
    result.notes[#result.notes + 1] = "Repeated observations are only a sample; uniform replies do not establish coverage of all backends."
  end
  return finish(result)
end
