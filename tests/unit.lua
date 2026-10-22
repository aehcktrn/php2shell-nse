-- Offline contract tests. Run from the repository root with:
--   lua tests/unit.lua
-- LuaTeX is also supported: luatex --luaonly tests/unit.lua
local root = (arg[0] or "tests/unit.lua"):match("^(.*[/\\])") or "tests/"
local script_path = root .. "../http-php2shell.nse"
local passed, failed = 0, 0

local function equal(actual, expected, message)
  if actual ~= expected then
    error((message or "unexpected value") .. ": expected " .. tostring(expected)
      .. ", got " .. tostring(actual), 2)
  end
end

local function truthy(value, message)
  if not value then error(message or "assertion failed", 2) end
end

local function contains(values, expected)
  for _, value in ipairs(values or {}) do
    if value == expected then return true end
  end
  return false
end

local function flatten(value, into)
  into = into or {}
  if type(value) == "table" then
    for key, item in pairs(value) do
      flatten(key, into)
      flatten(item, into)
    end
  else
    into[#into + 1] = tostring(value)
  end
  return table.concat(into, " ")
end

local function run(response, args, host, port)
  local calls = {}
  local modules = {
    http = {
      get = function(request_host, request_port, path, options)
        calls[#calls + 1] = {host = request_host, port = request_port,
          path = path, options = options}
        return response
      end,
    },
    shortport = {http = function() return true end},
    stdnse = {
      get_script_args = function(name) return (args or {})[name] end,
      output_table = function() return {} end,
      debug1 = function() end,
      debug2 = function() end,
      format_output = function(_, value) return value end,
    },
  }
  local env = setmetatable({SCRIPT_NAME = "http-php2shell"}, {__index = _G})
  env.require = function(name) return modules[name] or require(name) end
  local chunk, load_error = loadfile(script_path, "t", env)
  truthy(chunk, load_error)
  chunk()
  local result, human = env.action(host or {ip = "127.0.0.1", targetname = "app.example.test"},
    port or {number = 443, protocol = "tcp", service = "https", state = "open"})
  truthy(type(result) == "table", "action must return a structured result")
  equal(result.exploitability, "NOT_TESTED", "never claim exploitation was tested")
  truthy(type(result.reason) == "string" and #result.reason > 0, "provide a reason")
  local verdicts = {
    POTENTIALLY_VULNERABLE = "VULNERABLE PROBABLE (selon la version annoncee)",
    PATCHED_VERSION_ADVERTISED = "VERSION CORRIGEE ANNONCEE",
    UNKNOWN = "INDETERMINE - A VERIFIER",
  }
  equal(result.verdict, verdicts[result.state], "qualified human verdict")
  truthy(type(result.remediation) == "string" and #result.remediation > 0, "patch guidance absent")
  truthy(type(result.verification) == "string" and #result.verification > 0, "verification guidance absent")
  truthy(type(result.fixed_versions) == "table", "structured fix versions absent")
  equal(type(result.potentially_vulnerable_evidence), "boolean", "suspect evidence flag")
  truthy(type(human) == "string", "action must return human text as its second value")
  equal(human:sub(1, #result.verdict + 1), "\n" .. result.verdict, "human output must lead with the verdict")
  truthy(human:find("PHP : ", 1, true), "human output lacks PHP evidence")
  truthy(human:find("Correctif : " .. result.remediation, 1, true), "human output lacks remediation")
  truthy(human:find("Verification : " .. result.verification, 1, true), "human output lacks verification")
  return result, calls, human
end

local function response(value, extra)
  local item = {status = 200, header = {["x-powered-by"] = value}, body = "fixture"}
  for key, val in pairs(extra or {}) do item[key] = val end
  return item
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    passed = passed + 1
    io.write("ok - " .. name .. "\n")
  else
    failed = failed + 1
    io.write("not ok - " .. name .. "\n  " .. tostring(err) .. "\n")
  end
end

local version_cases = {
  {"8.2.34", "POTENTIALLY_VULNERABLE"}, {"8.2.35", "PATCHED_VERSION_ADVERTISED"},
  {"8.3.35", "POTENTIALLY_VULNERABLE"}, {"8.3.36", "PATCHED_VERSION_ADVERTISED"},
  {"8.4.26", "POTENTIALLY_VULNERABLE"}, {"8.4.27", "PATCHED_VERSION_ADVERTISED"},
  {"8.5.11", "POTENTIALLY_VULNERABLE"}, {"8.5.12", "PATCHED_VERSION_ADVERTISED"},
  {"8.3.9", "POTENTIALLY_VULNERABLE"}, {"8.3.100", "PATCHED_VERSION_ADVERTISED"},
  {"8.6.0alpha1", "POTENTIALLY_VULNERABLE"}, {"8.6.0beta3", "POTENTIALLY_VULNERABLE"},
  {"8.6.0RC3", "POTENTIALLY_VULNERABLE"}, {"8.6.0RC4", "PATCHED_VERSION_ADVERTISED"},
  {"8.6.0RC5", "PATCHED_VERSION_ADVERTISED"}, {"8.6.0", "PATCHED_VERSION_ADVERTISED"},
  {"8.6.1", "PATCHED_VERSION_ADVERTISED"},
  {"5.3.29", "POTENTIALLY_VULNERABLE"}, {"5.6.40", "POTENTIALLY_VULNERABLE"},
  {"7.4.33", "POTENTIALLY_VULNERABLE"}, {"8.0.30", "POTENTIALLY_VULNERABLE"},
  {"8.1.33", "POTENTIALLY_VULNERABLE"},
  {"8.3.6-0ubuntu0.24.04.6", "POTENTIALLY_VULNERABLE"},
  {"8.3.36-1+deb13u1", "PATCHED_VERSION_ADVERTISED"},
  {"8.5.12-dev", "UNKNOWN"}, {"8.3.36custom", "UNKNOWN"},
  {"8.3.36RC1", "UNKNOWN"}, {"8.3.36-rcX", "UNKNOWN"}, {"8.6.0-rc", "UNKNOWN"},
  {"8.3.36+RC1", "UNKNOWN"}, {"8.3.36-preview1", "UNKNOWN"}, {"8.6.0~beta", "UNKNOWN"},
  {"8.7.0", "UNKNOWN"}, {"9.0.0", "UNKNOWN"},
  {"8.3", "UNKNOWN"}, {"8", "UNKNOWN"}, {"8.3.x", "UNKNOWN"},
}
for _, case in ipairs(version_cases) do
  test("version " .. case[1], function()
    local result = run(response("PHP/" .. case[1]))
    equal(result.state, case[2])
  end)
end

test("CVE identifiers and evidence remain machine readable", function()
  local result = run(response("PHP/8.4.26"))
  equal(result.detection_method, "HTTP response headers (version-based)")
  truthy(contains(result.cves, "CVE-2026-109618"), "first CVE absent")
  truthy(contains(result.cves, "CVE-2026-109619"), "second CVE absent")
  equal(result.http_status, 200)
  truthy(contains(result.versions, "8.4.26"), "observed version absent")
  truthy(#result.evidence > 0, "evidence absent")
  equal(result.evidence[1].version, "8.4.26")
  equal(result.evidence[1].state, "POTENTIALLY_VULNERABLE")
  equal(result.evidence[1].fixed_version, "8.4.27")
end)

test("suspect version gives its branch fix and verification priority", function()
  local result, _, human = run(response("PHP/8.4.26"))
  equal(result.priority, "PATCH_OR_VERIFY_BACKPORT")
  equal(result.potentially_vulnerable_evidence, true)
  equal(#result.fixed_versions, 1)
  equal(result.fixed_versions[1], "8.4.27")
  truthy(result.remediation:find("8.4.27", 1, true), "correct branch patch absent")
  local advice = (result.remediation .. " " .. result.verification):lower()
  truthy(advice:find("backport", 1, true) or advice:find("retroport", 1, true), "vendor backport caveat absent")
  truthy(advice:find("redemarr", 1, true) or advice:find("restart", 1, true), "running workers restart absent")
  truthy(human:find("PHP : 8.4.26", 1, true))
end)

test("patched advertised version requests runtime confirmation", function()
  local result = run(response("PHP/8.3.36"))
  equal(result.priority, "CONFIRM_RUNTIME")
  equal(result.potentially_vulnerable_evidence, false)
  equal(#result.fixed_versions, 1)
  equal(result.fixed_versions[1], "8.3.36")
end)

test("missing evidence yields verification guidance rather than an all-clear", function()
  local result, _, human = run(nil)
  equal(result.priority, "VERIFY_RUNTIME")
  equal(result.potentially_vulnerable_evidence, false)
  equal(#result.fixed_versions, 0)
  truthy(human:find("PHP : non determine", 1, true))
  truthy(not human:find("VERSION CORRIGEE ANNONCEE", 1, true))
end)

test("conflicting evidence keeps suspicious versions a priority", function()
  local result = run({status = 200,
    header = {["x-powered-by"] = "PHP/8.3.36", server = "Apache PHP/8.4.26"}})
  equal(result.state, "UNKNOWN")
  equal(result.priority, "VERIFY_PRIORITY")
  equal(result.potentially_vulnerable_evidence, true)
  truthy(contains(result.fixed_versions, "8.3.36"))
  truthy(contains(result.fixed_versions, "8.4.27"))
end)

test("same branch conflict reports a unique fix version", function()
  local result = run({status = 200,
    header = {["x-powered-by"] = "PHP/8.3.36", server = "Apache PHP/8.3.35"}})
  equal(result.priority, "VERIFY_PRIORITY")
  equal(#result.fixed_versions, 1)
  equal(result.fixed_versions[1], "8.3.36")
end)

test("conflicting patched versions remain inconclusive without suspect evidence", function()
  local result = run(response("PHP/8.3.36, PHP/8.4.27"))
  equal(result.state, "UNKNOWN")
  equal(result.priority, "VERIFY_RUNTIME")
  equal(result.potentially_vulnerable_evidence, false)
end)

test("legacy branch guidance does not invent an upstream patch", function()
  local result = run(response("PHP/7.4.33"))
  equal(result.priority, "PATCH_OR_VERIFY_BACKPORT")
  equal(result.potentially_vulnerable_evidence, true)
  equal(#result.fixed_versions, 0)
  local advice = result.remediation:lower()
  truthy(advice:find("migr", 1, true), "legacy branch migration absent")
  truthy(advice:find("fournisseur", 1, true) or advice:find("vendor", 1, true), "vendor alternative absent")
end)

test("case insensitive PHP token", function()
  equal(run(response("pHp/8.3.35")).state, "POTENTIALLY_VULNERABLE")
end)

test("Server header can advertise PHP", function()
  local result = run({status = 200, header = {server = "Apache/2.4.58 PHP/8.5.11"}})
  equal(result.state, "POTENTIALLY_VULNERABLE")
end)

test("duplicate identical versions are not a conflict", function()
  local result = run({status = 200,
    header = {["x-powered-by"] = "PHP/8.3.36", server = "Apache PHP/8.3.36"}})
  equal(result.state, "PATCHED_VERSION_ADVERTISED")
end)

test("conflicting versions never produce an all-clear", function()
  local result = run({status = 200,
    header = {["x-powered-by"] = "PHP/8.3.36", server = "Apache PHP/8.3.35"}})
  equal(result.state, "UNKNOWN")
  truthy(contains(result.versions, "8.3.35") and contains(result.versions, "8.3.36"))
end)

test("multiple versions in one header preserve conflict", function()
  local result = run(response("PHP/8.3.35, PHP/8.3.36"))
  equal(result.state, "UNKNOWN")
  truthy(contains(result.versions, "8.3.35") and contains(result.versions, "8.3.36"))
end)

test("vendor suffix is preserved and backport limitation explained", function()
  local result = run(response("PHP/8.3.6-0ubuntu0.24.04.6"))
  truthy(contains(result.versions, "8.3.6-0ubuntu0.24.04.6"))
  truthy(flatten(result):lower():find("backport", 1, true), "backport caveat absent")
end)

test("hidden version is unknown", function()
  equal(run(response("PHP")).state, "UNKNOWN")
end)

test("unrelated headers and body are not version evidence", function()
  local result = run({status = 200, header = {server = "nginx", ["x-documentation"] = "PHP/8.5.12"},
    body = "<h1>PHP/8.5.12 example</h1>"})
  equal(result.state, "UNKNOWN")
end)

test("PHP lookalike product token is ignored", function()
  equal(run(response("NotPHP/8.3.36")).state, "UNKNOWN")
end)

test("hyphenated lookalike product token is ignored", function()
  equal(run(response("Not-PHP/8.3.36")).state, "UNKNOWN")
end)

test("dotted lookalike product token is ignored", function()
  equal(run(response("Not.PHP/8.3.36")).state, "UNKNOWN")
end)

test("HTTP error without PHP evidence is unknown", function()
  equal(run({status = 403, header = {}, body = "Forbidden"}).state, "UNKNOWN")
end)

test("empty HTTP response is unknown", function()
  equal(run(nil).state, "UNKNOWN")
end)

test("HTTP failure table is unknown", function()
  equal(run({["status-line"] = "ERROR: timeout"}).state, "UNKNOWN")
end)

test("cookies, complete headers and bodies are not leaked", function()
  local result, _, human = run(response("PHP/8.3.35", {
    rawheader = {"X-Powered-By: PHP/8.3.35", "Set-Cookie: session=TOP_SECRET_COOKIE"},
    cookies = {{name = "session", value = "TOP_SECRET_COOKIE"}},
    body = "TOP_SECRET_BODY",
  }))
  local output = flatten(result) .. human
  truthy(not output:find("TOP_SECRET_COOKIE", 1, true))
  truthy(not output:find("TOP_SECRET_BODY", 1, true))
end)

test("bounded GET has no redirect, cache, credentials or body", function()
  local _, calls = run(response("PHP/8.3.35"))
  equal(#calls, 1, "number of HTTP calls")
  equal(calls[1].path, "/")
  local opts = calls[1].options
  equal(opts.redirect_ok, false)
  equal(opts.bypass_cache, true)
  equal(opts.no_cache, true)
  equal(opts.max_body_size, 65536)
  equal(opts.timeout, 5000)
  equal(opts.truncated_ok, true)
  equal(opts.content, nil)
  equal(opts.auth, nil)
  equal(opts.cookies, nil)
end)

test("custom path and timeout are applied", function()
  local _, calls = run(response("PHP/8.3.35"), {
    ["http-php2shell.path"] = "/app/index.php?view=home",
    ["http-php2shell.timeout"] = "1500",
  })
  equal(calls[1].path, "/app/index.php?view=home")
  equal(calls[1].options.timeout, 1500)
end)

test("vhost preserves destination IP and sets TLS SNI and HTTP Host", function()
  local original = {ip = "192.0.2.10", targetname = "original.example.test"}
  local _, calls = run(response("PHP/8.3.35"), {
    ["http-php2shell.vhost"] = "application.example.test",
  }, original)
  equal(calls[1].host.ip, "192.0.2.10")
  equal(calls[1].host.targetname, "application.example.test")
  local headers = calls[1].options.header or {}
  equal(headers.Host or headers.host, "application.example.test")
  equal(original.targetname, "original.example.test", "shared host must not be mutated")
end)

test("duplicate raw headers cannot hide an older version", function()
  local result = run({status = 200,
    rawheader = {"X-Powered-By: PHP/8.3.35", "X-Powered-By: PHP/8.3.36"},
    header = {["x-powered-by"] = "PHP/8.3.36"}})
  equal(result.state, "UNKNOWN")
  truthy(contains(result.versions, "8.3.35") and contains(result.versions, "8.3.36"))
end)

test("truncated header evidence never yields an all-clear", function()
  local value = "PHP/8.3.36 " .. string.rep("x", 8200) .. " PHP/8.3.35"
  equal(run(response(value)).state, "UNKNOWN")
end)

test("excessive evidence is bounded and inconclusive", function()
  local values = {}
  for patch = 35, 80 do values[#values + 1] = "PHP/8.2." .. patch end
  local result = run(response(table.concat(values, ", ")))
  equal(result.state, "UNKNOWN")
  truthy(#result.evidence <= 32, "unbounded evidence list")
end)

test("generic http.host also aligns SNI with HTTP Host", function()
  local _, calls = run(response("PHP/8.3.36"), {["http.host"] = "generic.example.test"})
  equal(calls[1].host.ip, "127.0.0.1")
  equal(calls[1].host.targetname, "generic.example.test")
  equal(calls[1].options.header.Host, "generic.example.test")
end)

test("explicit vhost wins over generic http.host", function()
  local _, calls = run(response("PHP/8.3.36"), {
    ["http.host"] = "generic.example.test", ["http-php2shell.vhost"] = "specific.example.test"})
  equal(calls[1].host.targetname, "specific.example.test")
  equal(calls[1].options.header.Host, "specific.example.test")
end)

test("percent-encoded Unicode path is preserved", function()
  local _, calls = run(response("PHP/8.3.36"), {["http-php2shell.path"] = "/caf%C3%A9/index.php"})
  equal(calls[1].path, "/caf%C3%A9/index.php")
end)

local invalid_paths = {"https://outside.example/", "//outside.example/", "relative", "/bad path", "/bad\r\nHeader: x", "/fragment#x", "/\\outside.example/", "/tab\tpath", true, {"/"}}
for i, value in ipairs(invalid_paths) do
  test("invalid path rejected before HTTP #" .. i, function()
    local result, calls = run(response("PHP/8.3.35"), {["http-php2shell.path"] = value})
    equal(result.state, "UNKNOWN")
    equal(#calls, 0)
  end)
end
local invalid_vhosts = {"https://application.example.test", "app.example.test:443", "bad host", "app.example.test\r\nX: y", "app.example.test/path", true, {"host"}}
for i, value in ipairs(invalid_vhosts) do
  test("invalid vhost rejected before HTTP #" .. i, function()
    local result, calls = run(response("PHP/8.3.35"), {["http-php2shell.vhost"] = value})
    equal(result.state, "UNKNOWN")
    equal(#calls, 0)
  end)
end
for _, value in ipairs({"0", "-1", "60001", "1.5", "nan", "5s"}) do
  test("invalid timeout " .. value .. " rejected before HTTP", function()
    local result, calls = run(response("PHP/8.3.35"), {["http-php2shell.timeout"] = value})
    equal(result.state, "UNKNOWN")
    equal(#calls, 0)
  end)
end

io.write(string.format("\n%d passed; %d failed\n", passed, failed))
if failed > 0 then os.exit(1) end
