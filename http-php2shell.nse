local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Assesses possible exposure to PHP2Shell (CVE-2026-109618 and CVE-2026-109619)
from PHP versions advertised in the Server and X-Powered-By HTTP headers.

This is a version-based assessment, not an exploit or a confirmation that the
running service is vulnerable, patched, or compromised. Vendor backports are
not verified. Missing, conflicting, or unrecognized versions produce UNKNOWN.

The script makes a bounded GET request to one supplied path. It does not follow
redirects, submit multipart bodies, trigger memory exhaustion, or execute code.
HTTP and HTTPS are supported by Nmap's HTTP library.

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
  result.script_version = "0.2.0"
  result.advisory_date = "2026-10-21"
  result.cves = {"CVE-2026-109618", "CVE-2026-109619"}
  result.versions = {}
  result.evidence = {}
  result.notes = {
    "Headers are untrusted and can be hidden, altered, cached, or supplied by a proxy.",
    "Vendor backports are not verified; check the package/build used by the running web workers."
  }
  result.reason = "No reliable PHP version evidence was obtained."
  return result
end

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

  local lines = {
    result.verdict,
    "PHP : " .. (#result.versions > 0 and table.concat(result.versions, ", ") or "non determine"),
    "Correctif : " .. result.remediation,
    "Verification : " .. result.verification
  }
  if result.state == UNKNOWN then
    local detail
    if result.error then
      detail = result.error
    elseif not result.http_status then
      detail = "Aucune reponse HTTP exploitable; verifier la connexion et le service."
    elseif #result.versions > 1 then
      detail = "Versions PHP contradictoires; verifier chaque backend."
    elseif #result.evidence > 0 then
      detail = "Version ou preuves non conclusives; consulter les details dans le XML."
    elseif result.php_detected == "YES" then
      detail = "PHP annonce sans version exploitable."
    else
      detail = "Aucune version PHP exposee; PHP peut tout de meme etre present."
    end
    table.insert(lines, "Detail : " .. detail)
  end
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

local function parameters()
  local path = stdnse.get_script_args(PREFIX .. ".path")
  if path == nil then path = "/" end
  if type(path) ~= "string" or #path > 2048 or path:sub(1, 1) ~= "/"
      or path:sub(1, 2) == "//" or path:find("[%c%s#\\]") then
    return nil, "Invalid path: use a local /path without spaces, controls, backslashes, or a fragment."
  end
  local timeout = stdnse.get_script_args(PREFIX .. ".timeout")
  if timeout == nil then timeout = 5000 end
  if type(timeout) ~= "string" and type(timeout) ~= "number" then
    return nil, "Invalid timeout: expected an integer between 1 and 60000 milliseconds."
  end
  timeout = tonumber(timeout)
  if not timeout or timeout < 1 or timeout > 60000 or timeout % 1 ~= 0 then
    return nil, "Invalid timeout: expected an integer between 1 and 60000 milliseconds."
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
  return {path = path, timeout = timeout, vhost = vhost}
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
  elseif #result.versions > 1 then
    result.reason = "Conflicting PHP versions were advertised; inspect each evidence item and web worker."
  elseif #result.evidence > 0 then
    result.state = result.evidence[1].state
    result.reason = result.evidence[1].reason
  elseif php_seen then
    result.reason = "PHP is advertised without a usable version; patch status is indeterminate."
  else
    result.reason = "No PHP version advertised in Server or X-Powered-By; PHP may still be present."
  end
end

action = function(host, port)
  local result = output()
  local args, error_message = parameters()
  if not args then
    result.reason = error_message
    result.error = error_message
    return finish(result)
  end

  local request_host = {}
  for key, value in pairs(host) do request_host[key] = value end
  local headers = {["Accept-Encoding"] = "identity"}
  if args.vhost then
    request_host.targetname = args.vhost
    headers.Host = args.vhost
    if port.number ~= 80 and port.number ~= 443 then
      headers.Host = headers.Host .. ":" .. tostring(port.number)
    end
    result.vhost = args.vhost
  end

  local response = http.get(request_host, port, args.path, {
    header = headers,
    timeout = args.timeout,
    redirect_ok = false,
    bypass_cache = true,
    no_cache = true,
    max_body_size = 65536,
    truncated_ok = true
  })
  if type(response) ~= "table" or not tonumber(response.status) then
    result.reason = "No complete HTTP response; reachability and PHP patch status are indeterminate."
    return finish(result)
  end
  result.http_status = tonumber(response.status)
  extract(response, result)
  if result.http_status >= 300 and result.http_status < 400 then
    table.insert(result.notes, "Redirect not followed; this assessment only covers the responding endpoint.")
  elseif result.http_status >= 400 then
    table.insert(result.notes, "HTTP error response: advertised headers may belong to an intermediary.")
  end
  if response.truncated then
    table.insert(result.notes, "Response body truncated at 65536 bytes; the body is not used as evidence.")
  end
  return finish(result)
end
