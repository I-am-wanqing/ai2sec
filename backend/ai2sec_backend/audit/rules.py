"""D1-D10 detection rules distilled from the code-audit skill checklists.

Sources: code-audit-main/references/checklists/{python,javascript,universal}.md
Each rule: (dimension, id, title, severity, regex, description, recommendation)
Severity is raised automatically when taint-indicating input markers appear on
the same line (see scanner._taint_confidence).
"""

import re
from typing import List, NamedTuple, Pattern


class Rule(NamedTuple):
    dimension: str  # D1..D10
    rule_id: str
    title: str
    severity: str
    pattern: "Pattern[str]"
    description: str
    recommendation: str
    languages: tuple = ("python", "javascript", "typescript", "java", "go", "php")


def _r(rule_id: str, pattern: str) -> "Pattern[str]":
    return re.compile(pattern, re.MULTILINE)


# ---------------------------------------------------------------------------
# Language rules
# ---------------------------------------------------------------------------

LANGUAGE_RULES: List[Rule] = [
    # -- D1 Injection -------------------------------------------------------
    Rule(
        "D1", "PY-SQLI-CONCAT", "SQL query built by string concatenation", "high",
        _r("PY-SQLI-CONCAT", r"(?i)\b(execute|executemany)\s*\(\s*(f[\"']|['\"].*['\"]\s*(\+|%)|['\"].*['\"]\s*\.format\()"),
        "A database execute call receives a query built with f-string, % or concatenation; if any fragment is user-controlled this is SQL injection.",
        "Use parameterized queries: cursor.execute(sql, params). Never build SQL by string formatting.",
        ("python",),
    ),
    Rule(
        "D1", "PY-SQLI-ORM-RAW", "ORM raw SQL with interpolation", "high",
        _r("PY-SQLI-ORM-RAW", r"(?i)\b(raw|extra|RawSQL)\s*\(\s*(f[\"']|['\"].*['\"]\s*%|['\"].*['\"]\s*\+)"),
        "Django/SQLAlchemy raw()/extra()/RawSQL() called with an interpolated query string.",
        "Pass bound parameters to raw SQL APIs instead of interpolating values.",
        ("python",),
    ),
    Rule(
        "D1", "PY-CMDI", "Shell command with user-controllable string", "critical",
        _r("PY-CMDI", r"(?i)\b(os\.system|os\.popen|subprocess\.\w+)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(\s*f[\"']"),
        "A shell command is built or executed with shell=True; command injection leads to RCE when user input reaches the command string.",
        "Avoid shell=True; pass an argument list to subprocess.run and validate/allowlist every dynamic argument.",
        ("python",),
    ),
    Rule(
        "D1", "PY-EVAL", "eval()/exec() on dynamic string", "critical",
        _r("PY-EVAL", r"\b(eval|exec)\s*\("),
        "eval()/exec() executes arbitrary code; critical (RCE) if the argument can be influenced by user input.",
        "Remove eval/exec; parse data with json/ast.literal_eval or map allowed operations explicitly.",
        ("python",),
    ),
    Rule(
        "D1", "PY-SSTI", "Server-side template injection via render_template_string", "critical",
        _r("PY-SSTI", r"render_template_string\s*\(|Template\s*\(\s*[^)]*\)\s*\.render\("),
        "Jinja2 renders a dynamic template string; if user input reaches it, SSTI can escalate to RCE.",
        "Render static template files and pass user data as context variables only.",
        ("python",),
    ),
    Rule(
        "D1", "JS-SQLI-TEMPLATE", "SQL query built from template literal", "high",
        _r("JS-SQLI-TEMPLATE", r"(?i)\b(query|execute|raw)\s*\(\s*`[^`]*\$\{"),
        "A database call uses a template literal with ${} interpolation; SQL injection if the value is user-controlled.",
        "Use parameter placeholders (?) or tagged safe SQL builders; never interpolate values into SQL strings.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D1", "JS-CMDI", "child_process command execution", "critical",
        _r("JS-CMDI", r"child_process[.\s]+(exec|execSync)\s*\(|spawn\s*\([^)]*shell\s*:\s*true"),
        "child_process.exec / spawn(shell:true) runs a shell string; command injection if any part is user-controlled.",
        "Use execFile/spawn with an argument array and shell:false; validate dynamic arguments.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D1", "JS-EVAL", "eval / new Function on dynamic input", "critical",
        _r("JS-EVAL", r"\beval\s*\(|new\s+Function\s*\(|vm\.runIn\w+Context\s*\("),
        "eval/new Function/vm.runIn*Context execute dynamic code; RCE if the source is user-controlled.",
        "Remove dynamic code evaluation; use JSON.parse for data and explicit dispatch for logic.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D1", "PY-NOSQL-DICT-QUERY", "Query built directly from request data (ORM/NoSQL injection)", "high",
        _r("PY-NOSQL-DICT-QUERY", r"(?i)filter\s*\(\s*\*\*\s*(request\.(GET|POST)|data)"),
        "Query filters are expanded directly from request data; attackers can control query fields (ORM injection).",
        "Allowlist accepted filter fields explicitly before querying.",
        ("python",),
    ),
    Rule(
        "D1", "JS-NOSQL-DIRECT", "MongoDB query fed with raw request object", "high",
        _r("JS-NOSQL-DIRECT", r"(?i)\.(find|findOne|findOneAndUpdate)\s*\(\s*(req\.(query|body|params))"),
        "MongoDB query receives the raw request object; operators like $gt/$where can be injected.",
        "Validate and rebuild the query object server-side with only expected fields.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D1", "JAVA-SQLI-CONCAT", "SQL built by concatenation (Statement)", "high",
        _r("JAVA-SQLI-CONCAT", r"(?i)(createStatement|Statement)\s*[\s\S]{0,120}execute(Query|Update)?\s*\([^)]*\+"),
        "A Statement query is assembled with string concatenation; SQL injection if any fragment is user-controlled.",
        "Use PreparedStatement with bound parameters.",
        ("java",),
    ),

    # -- D2 Authentication --------------------------------------------------
    Rule(
        "D2", "PY-JWT-NONE", "JWT decode without signature verification", "critical",
        _r("PY-JWT-NONE", r"jwt\.decode\s*\(|algorithms\s*=\s*\[?\s*[\"']none[\"']|verify\s*=\s*False"),
        "JWT is decoded without verified signature or with algorithm 'none'/verify disabled — authentication bypass.",
        "Use jwt.decode(token, key, algorithms=['HS256']) and always verify the signature and expiry.",
        ("python",),
    ),
    Rule(
        "D2", "JS-JWT-DECODE", "jwt.decode without jwt.verify", "critical",
        _r("JS-JWT-DECODE", r"jwt\.decode\s*\(|algorithms\s*:\s*\[\s*[\"']none[\"']"),
        "jwt.decode only base64-decodes the payload; without jwt.verify the token is attacker-forged.",
        "Always verify tokens with jwt.verify and an explicit algorithm allowlist.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D2", "AUTH-BYPASS-RESIDUE", "Suspicious auth bypass residue", "high",
        _r("AUTH-BYPASS-RESIDUE", r"(?i)(skip[_-]?auth|bypass[_-]?auth|auth[_-]?bypassed?|is[_-]?admin\s*=\s*true|DEBUG.*return\s+True)"),
        "Code contains authentication bypass residue such as skip_auth flags or debug backdoors.",
        "Remove bypass logic; gate any test-only path behind a build/test-only flag that cannot ship.",
    ),
    Rule(
        "D2", "PY-FLASK-NO-AUTH", "Flask routes without @login_required", "medium",
        _r("PY-FLASK-NO-AUTH", r"@app\.route\(|@blueprint\.route\("),
        "A Flask route is registered; verify it has an authentication decorator or is intentionally public.",
        "Add @login_required (or equivalent dependency) to every sensitive route; review the route allowlist.",
        ("python",),
    ),
    Rule(
        "D2", "PY-CSRF-EXEMPT", "csrf_exempt on state-changing view", "medium",
        _r("PY-CSRF-EXEMPT", r"@csrf_exempt"),
        "@csrf_exempt disables CSRF protection; if applied to a state-changing view it enables CSRF attacks.",
        "Remove csrf_exempt or scope it to token-verified webhook endpoints only.",
        ("python",),
    ),
    Rule(
        "D2", "PY-WEAK-RATE-LIMIT", "No rate limiting on credential endpoints", "medium",
        _r("PY-WEAK-RATE-LIMIT", r"(?i)(login|signin|password|otp|verify[_-]?code)"),
        "Credential-related code found; ensure brute-force protection (rate limit / lockout) is enforced server-side.",
        "Add per-account and per-IP throttling plus exponential backoff on failures.",
        ("python", "javascript", "typescript"),
    ),

    # -- D3 Authorization ---------------------------------------------------
    Rule(
        "D3", "IDOR-UNSCOPED-GET", "Resource fetched by ID without ownership scope", "high",
        _r("IDOR-UNSCOPED-GET", r"(?i)(get_object\s*\(|objects\.get\s*\(\s*(pk\s*=|id\s*=)|findById\s*\(|getByIds?\s*\()"),
        "A resource is fetched by raw ID; if the handler does not additionally scope by owner/tenant this is IDOR.",
        "Scope queries by the authenticated owner (e.g. objects.get(id=id, user=request.user)) and check permissions on every CRUD action.",
    ),
    Rule(
        "D3", "ADMIN-NO-ROLE-CHECK", "Admin endpoint without role guard", "high",
        _r("ADMIN-NO-ROLE-CHECK", r"(?i)@(app|blueprint|router)\.(route|get|post|put|delete)\s*\(\s*[\"'][^\"']*(admin|manage|internal)"),
        "An admin-named endpoint is registered; confirm it enforces a server-side role check.",
        "Require an admin role check in middleware/dependency, not by hiding UI elements.",
    ),
    Rule(
        "D3", "MASS-ASSIGNMENT", "Request body bound directly to model", "high",
        _r("MASS-ASSIGNMENT", r"(?i)(ModelForm|Model\.create|\.save\s*\(\s*request\.(body|POST)|Model\s*\(\s*\*\*request\.|fields\s*=\s*[\"']__all__[\"']|Model\.create\s*\(\s*req\.body)"),
        "Request data is bound directly to a model; sensitive fields (role/is_admin/tenant) can be mass-assigned.",
        "Declare explicit field allowlists in forms/serializers and never bind privileged fields from request data.",
    ),

    # -- D4 Deserialization / prototype pollution ---------------------------
    Rule(
        "D4", "PY-PICKLE", "pickle used on potentially untrusted data", "critical",
        _r("PY-PICKLE", r"\bpickle\.loads?\s*\(|\bmarshal\.loads\s*\(|shelve\.open\s*\("),
        "pickle/marshal/shelve deserialize arbitrary objects; RCE if data comes from uploads, network or cache.",
        "Use JSON or msgpack; if pickle is unavoidable, apply an HMAC over the payload and restrict sources.",
        ("python",),
    ),
    Rule(
        "D4", "PY-YAML-UNSAFE", "yaml.load without SafeLoader", "critical",
        _r("PY-YAML-UNSAFE", r"yaml\.load\s*\((?![^)]*SafeLoader)"),
        "yaml.load without SafeLoader can instantiate arbitrary Python objects (RCE).",
        "Use yaml.load(data, Loader=yaml.SafeLoader) or yaml.safe_load().",
        ("python",),
    ),
    Rule(
        "D4", "JS-PROTO-POLLUTION", "Recursive merge of user input (prototype pollution)", "high",
        _r("JS-PROTO-POLLUTION", r"(?i)(Object\.assign\s*\([^,]+,\s*(req\.|request\.|user)|_\.merge\s*\(|_\.defaultsDeep\s*\(|node-serialize)"),
        "User-controlled objects are merged recursively; __proto__/constructor pollution can escalate to RCE in template engines.",
        "Sanitize keys (__proto__, constructor, prototype) before merging; use structured cloning with field allowlists.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D4", "JS-YAML-UNSAFE", "js-yaml load with default schema", "high",
        _r("JS-YAML-UNSAFE", r"(?i)yaml\.load\s*\((?![^)]*JSON_SCHEMA|[^)]*FAILSAFE_SCHEMA)"),
        "js-yaml load with default schema allows !!js/function — RCE on untrusted input.",
        "Load with schema: yaml.JSON_SCHEMA or yaml.FAILSAFE_SCHEMA.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D4", "JAVA-DESER", "Java native deserialization of untrusted data", "critical",
        _r("JAVA-DESER", r"new\s+ObjectInputStream\s*\(|readObject\s*\(|JSON\.parseObject\s*\("),
        "Java native deserialization or fastjson parseObject on untrusted data can trigger gadget-chain RCE.",
        "Avoid ObjectInputStream on untrusted data; prefer JSON with typed DTOs; for fastjson enable safeMode.",
        ("java",),
    ),
    Rule(
        "D4", "PHP-DESER", "PHP unserialize on user input", "critical",
        _r("PHP-DESER", r"(?i)unserialize\s*\("),
        "unserialize() on user-controlled data enables PHP object injection and POP-chain RCE.",
        "Use json_decode; if unserialize is required, use allowed_classes and sign the payload.",
        ("php",),
    ),

    # -- D5 File operations -------------------------------------------------
    Rule(
        "D5", "PATH-TRAVERSAL", "File path built from user-controllable segment", "high",
        _r("PATH-TRAVERSAL", r"(?i)(send_file\s*\(|send_from_directory\s*\(|FileResponse\s*\(|res\.download\s*\(|res\.sendFile\s*\()[^)]*(request|req\.|params|user|filename)"),
        "A file response is built with a request-derived path; ../ sequences can read arbitrary files.",
        "Normalize the resolved path and verify it stays inside the intended base directory; never trust raw filenames.",
    ),
    Rule(
        "D5", "OPEN-USER-PATH", "open()/fs read/write with dynamic path", "medium",
        _r("OPEN-USER-PATH", r"(?i)\bopen\s*\(\s*(f[\"']|['\"][^'\"]*['\"]\s*\+|os\.path\.join\s*\([^)]*(request|filename|user))|fs\.(readFile|writeFile|createReadStream)\s*\(\s*(req\.|`[^`]*\$\{)"),
        "A file is opened with a dynamically built path; confirm it cannot be driven outside the base directory.",
        "Resolve and validate paths against an allowlisted base; strip ../ and absolute-path segments.",
    ),
    Rule(
        "D5", "ZIP-SLIP", "Archive extraction without entry path validation", "high",
        _r("ZIP-SLIP", r"(?i)(extractall\s*\(|tarfile\.open|adm-zip|extract)\s*"),
        "Archive extraction is performed; without per-entry path validation an archive can write outside the target dir (Zip Slip).",
        "Validate every entry resolves inside the destination before extraction; reject absolute paths and symlinks.",
    ),
    Rule(
        "D5", "UPLOAD-NO-VALIDATION", "File upload without extension/MIME validation", "medium",
        _r("UPLOAD-NO-VALIDATION", r"(?i)(request\.files|multer|formidable|\.save\s*\(\s*secure)|multipart"),
        "An upload path exists; confirm extension/MIME allowlists, size limits and non-web-root storage.",
        "Allowlist extensions and MIME types, store outside web root with random names, and scan content.",
    ),

    # -- D6 SSRF ------------------------------------------------------------
    Rule(
        "D6", "SSRF-FETCH-USER-URL", "Server-side request with user-controllable URL", "high",
        _r("SSRF-FETCH-USER-URL", r"(?i)(requests\.(get|post|put|head)\s*\(|httpx\.(get|post)\s*\(|urllib\.request\.urlopen\s*\(|urlopen\s*\(|axios\.(get|post)\s*\(|fetch\s*\(|got\s*\()[^)]*(request|req\.|user|\burl\b|params|query|callback|webhook)"),
        "An outbound HTTP request receives a URL derived from request data; classic SSRF (cloud metadata, internal services).",
        "Allowlist destination hosts/schemes, resolve and block private/link-local IPs (incl. 169.254.169.254, ::1), and disable redirects.",
    ),
    Rule(
        "D6", "SSRF-STARTSWITH-WHITELIST", "URL validation by prefix match", "medium",
        _r("SSRF-STARTSWITH-WHITELIST", r"(?i)(startsWith|startswith|\.match\s*\(\s*[\"']https?://)",
        ),
        "URL allowlist uses string prefix matching; bypassable via https://allowed.com.evil.com or userinfo tricks.",
        "Parse the URL and compare the parsed hostname against an exact allowlist.",
    ),

    # -- D7 Cryptography ----------------------------------------------------
    Rule(
        "D7", "WEAK-HASH-PASSWORD", "Weak hash used for passwords", "medium",
        _r("WEAK-HASH-PASSWORD", r"(?i)(hashlib\.(md5|sha1)\s*\(|createHash\s*\(\s*[\"'](md5|sha1)[\"']|DES|RC4)"),
        "MD5/SHA1/DES/RC4 used in a security context (e.g. password storage) — fast and collision-prone.",
        "Use bcrypt/scrypt/argon2 for passwords; SHA-256+ for integrity checks.",
    ),
    Rule(
        "D7", "WEAK-RANDOM", "Math.random / random module for security values", "high",
        _r("WEAK-RANDOM", r"(?i)(Math\.random\s*\(\s*\)|(?<!\w)random\.(random|randint|choice)\s*\()"),
        "A non-CSPRNG is used where security tokens/codes are likely generated — predictable values.",
        "Use secrets module / crypto.randomBytes / crypto.randomUUID for any security-relevant value.",
    ),
    Rule(
        "D7", "ECB-MODE", "AES-ECB or static IV usage", "medium",
        _r("ECB-MODE", r"(?i)(MODE_ECB|aes-\d+-ecb|createCipheriv\s*\([^)]*[\"']ecb[\"'])"),
        "ECB mode leaks plaintext structure; a static/hardcoded IV also breaks semantic security.",
        "Use AES-GCM or CBC with a random per-message IV and an authenticated mode.",
    ),
    Rule(
        "D7", "INSECURE-VERIFY", "Certificate verification disabled", "high",
        _r("INSECURE-VERIFY", r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0)"),
        "TLS certificate verification is disabled, enabling MITM.",
        "Always verify certificates; pinning for internal services if needed.",
    ),

    # -- D8 Configuration ---------------------------------------------------
    Rule(
        "D8", "DEBUG-ON", "Debug mode enabled", "high",
        _r("DEBUG-ON", r"(?i)(DEBUG\s*=\s*True|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*[\"']?1|NODE_ENV\s*=\s*['\"]development['\"])"),
        "Debug mode is enabled in shipped code — stack traces / Werkzeug debugger can leak secrets or give RCE.",
        "Force debug off in production and gate it behind an environment flag defaulting to false.",
    ),
    Rule(
        "D8", "CORS-WILDCARD", "Overly permissive CORS", "high",
        _r("CORS-WILDCARD", r"(?i)(allow_origins\s*=\s*\[\s*[\"']\*[\"']|origin\s*:\s*[\"']\*[\"']|Access-Control-Allow-Origin['\"]?\s*[:,]\s*[\"']\*[\"']|allowed\s*origins?\s*:\s*[\"']\*[\"'])"),
        "CORS allows any origin; combined with credentials this lets any site read authenticated responses.",
        "Enumerate trusted origins explicitly; never combine wildcard origins with credentials.",
    ),
    Rule(
        "D8", "ALLOWED-HOSTS-STAR", "ALLOWED_HOSTS wildcard", "medium",
        _r("ALLOWED-HOSTS-STAR", r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']"),
        "ALLOWED_HOSTS = ['*'] disables Host header validation (cache poisoning / password reset poisoning).",
        "List the exact production hostnames.",
        ("python",),
    ),
    Rule(
        "D8", "SWS-EXPOSED", "Debug/management endpoints exposed", "medium",
        _r("SWS-EXPOSED", r"(?i)(/actuator|/debug|/pprof|/swagger-ui|/api-docs|/graphql)"),
        "A debug/management endpoint path appears in source; ensure it is disabled or authenticated in production.",
        "Disable actuator/pprof/swagger in production or put them behind authentication.",
    ),
    Rule(
        "D8", "LOG-SECRETS", "Secrets written to logs", "medium",
        _r("LOG-SECRETS", r"(?i)(print|log(ger|ging)?\.?(info|debug|warning|error)?)\s*\([^)]*(password|token|secret|api[_-]?key)"),
        "Credentials appear in a log/print statement — secrets leak into log storage.",
        "Redact sensitive fields before logging; never log raw credentials or tokens.",
    ),

    # -- D9 Business logic --------------------------------------------------
    Rule(
        "D9", "XSS-SINK", "XSS sink with dynamic HTML", "high",
        _r("XSS-SINK", r"(?i)(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html)"),
        "A DOM XSS sink is used; if the value derives from user input this is stored/reflected XSS.",
        "Render user content as text; sanitize with DOMPurify when HTML is genuinely required.",
        ("javascript", "typescript"),
    ),
    Rule(
        "D9", "RACE-NO-LOCK", "Read-modify-write without lock", "medium",
        _r("RACE-NO-LOCK", r"(?i)(select_for_update|transaction\.atomic|with_for_update|findOneAndUpdate)"),
        "Concurrency-control markers found; verify balances/stock updates run inside locked transactions.",
        "Wrap read-modify-write flows in transactions with row locks; use atomic UPDATE statements.",
    ),
    Rule(
        "D9", "CLIENT-CONTROLLED-AMOUNT", "Amount/price taken from client", "high",
        _r("CLIENT-CONTROLLED-AMOUNT", r"(?i)(amount|price|total|balance|discount)\s*[=:]\s*(request\.|req\.(body|query)|data\.get|input\[)"),
        "A money-related value is assigned directly from client input; classic payment bypass.",
        "Recompute amounts/limits server-side from authoritative records; treat client values as hints only.",
    ),
    Rule(
        "D9", "REDIRECT-USER-URL", "Open redirect with user-controlled URL", "medium",
        _r("REDIRECT-USER-URL", r"(?i)(redirect\s*\(|res\.redirect\s*\(|location\.href\s*=)\s*[^)]*(request|req\.|query|params|next)"),
        "A redirect target comes from request data — open redirect (and token leak via referer).",
        "Allowlist redirect targets or map opaque keys to fixed URLs.",
    ),
]

# ---------------------------------------------------------------------------
# Universal rules (language independent, whole-text)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[Rule] = [
    Rule(
        "D7", "SECRET-AWS-KEY", "AWS access key committed in source", "critical",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "An AWS access key ID pattern is committed in source — credential exposure.",
        "Rotate the key immediately, remove from source history, and move secrets to a secret manager.",
    ),
    Rule(
        "D7", "SECRET-PRIVATE-KEY", "Private key committed in source", "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "A private key PEM block is committed in source.",
        "Rotate the key, remove it from the repository and history, use a secret manager.",
    ),
    Rule(
        "D7", "SECRET-TOKEN", "Hardcoded API token / secret", "high",
        re.compile(r"(?i)(api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
        "A hardcoded secret-like literal was found; likely credential exposure.",
        "Move the value to environment/secret manager and rotate the credential.",
    ),
    Rule(
        "D7", "SECRET-HARDCODED-KEY", "Hardcoded symmetric key material", "high",
        re.compile(r"(?i)(SECRET_KEY|secretKey|encryption[_-]?key|ENCRYPTION_KEY)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        "A hardcoded SECRET_KEY / encryption key — secret disclosure if source leaks.",
        "Load keys from environment/secret manager with a safe default that refuses to boot in production.",
    ),
]

# ---------------------------------------------------------------------------
# Dependency CVE quick list (D10), from skill language checklists
# ---------------------------------------------------------------------------

DEPENDENCY_CVES = {
    "python": [
        ("pyyaml", "6.0", "RCE via yaml.load without SafeLoader"),
        ("jinja2", "2.11.3", "SSTI / sandbox escape"),
        ("django", "4.2", "multiple (SQLi, XSS, CSRF bypass)"),
        ("flask", "2.3.0", "debugger PIN prediction"),
        ("pillow", "9.3.0", "image parsing buffer overflow"),
        ("paramiko", "2.10.1", "CVE-2023-48795 Terrapin"),
        ("requests", "2.31.0", "credential leak on cross-origin redirect"),
        ("cryptography", "41.0", "OpenSSL issues"),
        ("celery", None, "pickle serialization RCE when queue exposed"),
        ("numpy", "1.22", "RCE via numpy.load(allow_pickle=True)"),
    ],
    "javascript": [
        ("lodash", "4.17.21", "prototype pollution"),
        ("express", "4.19.2", "path traversal / open redirect"),
        ("jsonwebtoken", "9.0.0", "alg 'none' confusion"),
        ("axios", "1.6.0", "credential leak on redirect"),
        ("node-serialize", None, "unserialize() RCE (no safe usage)"),
        ("js-yaml", "4.0.0", "default schema allows !!js/function"),
        ("handlebars", "4.7.7", "prototype pollution to RCE"),
        ("ejs", "3.1.7", "prototype pollution to RCE"),
        ("minimist", "1.2.6", "__proto__ injection"),
        ("mongoose", "6.0.0", "query selector injection"),
    ],
}


def rules_for_language(language: str) -> List[Rule]:
    return [rule for rule in LANGUAGE_RULES if language in rule.languages]


def all_rule_ids() -> List[str]:
    return [rule.rule_id for rule in LANGUAGE_RULES + SECRET_PATTERNS]
