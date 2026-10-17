#!/usr/bin/env python3
"""Static, read-only safety scan of an untrusted repo folder or zip.

Never executes, imports, or extracts anything from the target. Run it from
outside the repo, isolated:  python3 -I scan_repo.py <folder-or-zip>
"""
import json
import os
import re
import sys
import zipfile
from collections import defaultdict

MAX_BYTES = 25 * 1024 * 1024
SKIP_DIRS = {"node_modules", ".pnpm-store", ".yarn", ".next", ".turbo", "coverage", "__pycache__", ".venv", "venv",
             "Pods", ".cxx", ".gradle", ".expo", "DerivedData", "build", "dist", "out", ".output", "target", ".dart_tool",
             ".svelte-kit", ".vercel", ".netlify", ".cache", ".parcel-cache", ".angular", "vendor", "generated"}
GIT_KEEP = re.compile(r"(?:^|/)\.git/(?:modules/[^/]+/)*(?:config|hooks/[^/]+|info/[^/]+)$")
BUILD_DIRS = {"dist", "build", "out", ".output", "vendor"}

CODE_EXT = {".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".ipynb", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".rb", ".php", ".pl"}
TEXT_EXT = CODE_EXT | {".json", ".md", ".mdx", ".txt", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env",
                       ".html", ".htm", ".svg", ".xml", ".css", ".scss", ".sample", ".gitattributes", ".gitignore",
                       ".npmrc", ".nvmrc", ".editorconfig", ".sol", ".rs", ".go", ".java", ".kt", ".swift", ".prisma", ".sql"}
AGENT_FILES = {"claude.md", "agents.md", ".cursorrules", "copilot-instructions.md", ".windsurfrules", "gemini.md", "skill.md"}

STANDARD_HOOK_SAMPLES = {
    "applypatch-msg.sample", "commit-msg.sample", "fsmonitor-watchman.sample", "post-update.sample",
    "pre-applypatch.sample", "pre-commit.sample", "pre-merge-commit.sample", "pre-push.sample",
    "pre-rebase.sample", "pre-receive.sample", "prepare-commit-msg.sample", "push-to-checkout.sample",
    "sendemail-validate.sample", "update.sample",
}

AI_WORDS = r"(?:ai|a\.i\.|llm|llms|ai\s+assistants?|coding\s+assistants?|assistants?|ai\s+agents?|coding\s+agents?|claude|copilot|chatgpt|gpt-?\d|gemini|codex|cursor\s+ai|language\s+models?)"
AI_DIRECTED = [
    re.compile(r"(?:^|[#;/*>`-]\s*|[.!:]\s+)(?:please\s+)?(?:never|do\s*not|don'?t|dont|must\s*not)\s+(?:ever\s+)?(?:investigate|inspect|read|open|look\s+(?:at|into|inside)|scan|analy[sz]e|audit|review|check|explore|examine|decode|view|cat|print)\b[^\n]{0,60}?(?:\.git\b|files?\b|folders?\b|director(?:y|ies)\b|dir\b|hooks?\b|config\b|node_modules|\.env|this\b|these\b|[\w-]+\.[a-z]{1,5}\b|/)", re.I),
    re.compile(r"\b(?:ignore|skip|exclude|disregard)\s+(?:this|the|that|these|those|any|all)\s+(?:file|files|folder|folders|directory|directories|dir|code|section|path|hook|hooks|config|script|scripts)\b", re.I),
    re.compile(r"\b" + AI_WORDS + r"\b[^\n]{0,60}\b(?:ignore|skip|(?:must|should|do|does|need)\s*(?:not|n'?t)\s+(?:ever\s+)?(?:read|open|inspect|investigate|look|review|scan|audit|check|explore|examine|touch|analy[sz]e)|never\s+(?:read|open|inspect|investigate|look|review|scan|audit|check|explore|examine|touch|analy[sz]e))\b[^\n]{0,50}?(?:\.git\b|files?\b|folders?\b|director(?:y|ies)\b|dir\b|hooks?\b|config\b|node_modules|\.env|this\b|these\b|[\w-]+\.[a-z]{1,5}\b)", re.I),
    re.compile(r"\b(?:ignore|disregard)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts)\b", re.I),
]
BENIGN_DIRECTIVE = re.compile(r"auto-?generated|generated\s+(?:file|code|by)|do\s+not\s+(?:edit|modify|change)\s+(?:this|manually|by\s+hand)|eslint|prettier|istanbul|ts-?ignore|noqa|pylint|lint", re.I)

CODE_RULES = [
    ("HIGH", re.compile(r"spawn\w*\s*\(\s*process\.execPath|execPath\s*,\s*\[\s*['\"]-e['\"]"), "spawns a copy of node with inline code (classic detached loader)"),
    ("HIGH", re.compile(r"detached\s*:\s*true"), "starts a detached background process that outlives the app"),
    ("HIGH", re.compile(r"eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape|\w+\.data\b|r\.data|res\.data|response\.data)"), "evaluates decoded or downloaded code"),
    ("HIGH", re.compile(r"new\s+Function\s*\(\s*(?!['\"`])"), "builds a function from a non-literal string"),
    ("HIGH", re.compile(r"writeFile(?:Sync)?\s*\([^)]*node_modules"), "writes into node_modules at runtime"),
    ("HIGH", re.compile(r"(?:/Login Data\b|/Local State\b|/Network/Cookies\b|/Default/Cookies\b|Cookies\.binarycookies|login\.keychain|find-generic-password|dump-keychain|\.ssh/id_(?:rsa|ed25519|ecdsa)|wallet\.dat|Application Support/(?:Google/Chrome|BraveSoftware|Microsoft Edge|Arc|Exodus|atomic)|User Data/(?:Default|Profile)|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ejbalbakoplchlghecdalmeeeajnimhm)"), "reads browser credential stores, keychain, SSH keys or crypto wallets"),
    ("HIGH", re.compile(r"JSON\.stringify\s*\(\s*process\.env\s*\)|os\.environ\.copy\(\)"), "serialises the whole environment (secret exfiltration pattern)"),
    ("HIGH", re.compile(r"\bcurl\b[^\n|]{0,200}\|\s*(?:ba|z)?sh\b|\bwget\b[^\n|]{0,200}\|\s*(?:ba|z)?sh\b"), "downloads and pipes straight into a shell"),
    ("MEDIUM", re.compile(r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)|from\s+['\"](?:node:)?child_process['\"]|\bsubprocess\.(?:Popen|run|call)|os\.system\("), "can run system commands"),
    ("MEDIUM", re.compile(r"(?<![\w.])eval\s*\("), "uses eval"),
    ("MEDIUM", re.compile(r"\batob\s*\("), "decodes base64 at runtime"),
    ("MEDIUM", re.compile(r"createDecipheriv\s*\("), "decrypts embedded data (check where the key and ciphertext come from)"),
    ("MEDIUM", re.compile(r"(?<![\w.])require\s*\(\s*(?!['\"`])[A-Za-z_$][\w$.\[\]'\"]*\s*\)"), "require() of a non-literal module name"),
    ("MEDIUM", re.compile(r"writeFile(?:Sync)?\s*\(\s*(?:path\.join|path\.resolve)\s*\(\s*process\.cwd\(\)\s*,\s*(?!['\"`])"), "writes to a path built from runtime data under the working directory"),
    ("MEDIUM", re.compile(r"readUInt32BE\s*\(\s*\w+\.length\s*-\s*4\s*\)|\.subarray\s*\(\s*\w+\.length\s*-"), "reads a length-prefixed blob from the END of a file (stego carrier pattern)"),
    ("MEDIUM", re.compile(r"Buffer\.from\s*\(\s*['\"][A-Za-z0-9+/=]{200,}['\"]\s*,\s*['\"](?:base64|hex)['\"]"), "large embedded base64/hex blob"),
]
OBFUSCATION = re.compile(r"\b(?:_0x|a0_0x)[0-9a-f]{4,}\b")
OFFSCREEN = re.compile(r"\S {80,}\S|^ {150,}\S")
BIDI = re.compile("[‪-‮⁦-⁩]")
ZERO_WIDTH = re.compile("[​-‍⁠﻿]")

URL_RE = re.compile(r"https?://[^\s'\"`)<>]+", re.I)
IP_RE = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
SUSPICIOUS_HOSTS = re.compile(r"(?:\.vercel\.app|ngrok|trycloudflare|pastebin|paste\.ee|hastebin|rentry|bit\.ly|tinyurl|short\.gy|is\.gd|rebrand\.ly|cutt\.ly|raw\.githubusercontent|gist\.githubusercontent|discord(?:app)?\.com/api/webhooks|api\.telegram\.org|drpc\.org|publicnode|bsc-dataseed|trongrid|api\.npoint\.io|jsonkeeper|glitch\.me|replit\.app)", re.I)
ODD_DEPS = {"glogg": "gulp-internal logger; loads `sparkles`, which a real dropper overwrote to gain execution",
            "sparkles": "gulp-internal event store; a real dropper overwrote it to gain execution"}


class Scan:
    def __init__(self):
        self.findings = []
        self.notes = defaultdict(list)

    def add(self, sev, path, line, msg, snippet=""):
        snippet = re.sub(r"\s+", " ", snippet.strip())
        if len(snippet) > 160:
            snippet = snippet[:157] + "..."
        self.findings.append((sev, path, line, msg, snippet))


def is_texty(path, data):
    base = os.path.basename(path).lower()
    ext = os.path.splitext(base)[1]
    if ext in TEXT_EXT or base in AGENT_FILES or "/.git/" in "/" + path and "/objects/" not in path:
        return True
    return b"\x00" not in data[:8192] and len(data) < 5 * 1024 * 1024 and ext not in {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".zip"}


def check_git_config(s, path, text):
    section = ""
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("#", ";")):
            hit = any(p.search(line) for p in AI_DIRECTED)
            s.add("HIGH" if hit else "MEDIUM", path, i,
                  "comment inside .git/config" + (" telling someone (or an AI) not to look" if hit else " (git never writes these)"), line)
            continue
        m = re.match(r"\[([^\]]+)\]", line)
        if m:
            section = m.group(1).lower()
            continue
        key = line.split("=", 1)[0].strip().lower()
        val = line.split("=", 1)[1].strip() if "=" in line else ""
        if key == "fsmonitor" and val.lower() not in ("false", "true", "0", "1"):
            s.add("HIGH", path, i, "core.fsmonitor runs this command on every git status/diff/add (editors and AI tools trigger it on open)", line)
        elif key == "hookspath":
            inside = not val.startswith(("/", "~")) and ".." not in val
            s.add("MEDIUM" if inside else "HIGH", path, i, "hooks run from a custom folder; read every file there" + ("" if inside else " (points OUTSIDE the repo)"), line)
        elif key in ("sshcommand", "pager", "editor", "askpass", "gitproxy") or (section.startswith("filter") and key in ("clean", "smudge", "process")):
            s.add("HIGH", path, i, f"git will execute this configured command ({key})", line)
        elif section.startswith("alias") and val.startswith("!"):
            s.add("MEDIUM", path, i, "shell alias in repo git config", line)
        elif section.startswith("include") and key == "path":
            s.add("HIGH", path, i, "git config pulls in another config file", line)


def check_git_hook(s, path, data):
    name = os.path.basename(path)
    text = data.decode("utf-8", "replace")
    if not name.endswith(".sample"):
        s.add("HIGH", path, 0, "LIVE git hook (no .sample suffix) - runs on git operations", text[:120])
        return
    if name not in STANDARD_HOOK_SAMPLES:
        s.add("HIGH", path, 0, f"'{name}' is not a hook sample git ships - likely a disguised payload ({len(data)} bytes)", text[:120])
    elif len(data) > 6000:
        s.add("HIGH", path, 0, f"standard hook sample is unusually large ({len(data)} bytes; real ones are 0.2-5 KB)", text[:120])
    if re.search(r"require\(|_0x[0-9a-f]{4}|eval\(|child_process|const\s+\w+\s*=", text):
        s.add("HIGH", path, 0, "hook 'sample' contains JavaScript (real samples are shell/perl)", text[:120])
    if len(data) == 0:
        s.add("MEDIUM", path, 0, "empty hook sample - payloads often wipe themselves after running")


def check_package_json(s, path, text):
    try:
        pkg = json.loads(text)
    except Exception:
        return
    scripts = pkg.get("scripts") or {}
    for k, v in scripts.items():
        v = str(v)
        if k in ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare", "prestart", "predev"):
            benign = k == "prepare" and re.fullmatch(r"\s*(?:husky(?:\s+install)?|svelte-kit sync|nuxt prepare|panda codegen)\s*", v)
            s.add("INFO" if benign else "MEDIUM", path, 0, f"lifecycle script '{k}' runs automatically", f"{k}: {v}")
        if re.search(r"curl|wget|node\s+-e|bash\s+-c|powershell|base64|\|\s*(?:ba)?sh\b|https?://", v, re.I):
            s.add("HIGH", path, 0, f"script '{k}' downloads or runs inline code", f"{k}: {v}")
        if re.search(r"node\s+\.?/?\.git/", v):
            s.add("HIGH", path, 0, f"script '{k}' executes a file inside .git", f"{k}: {v}")
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (pkg.get(sec) or {}).items():
            spec = str(spec)
            if re.match(r"(?:git\+|git:|https?:|github:|file:|link:|[\w-]+/[\w.-]+(?:#|$))", spec):
                s.add("MEDIUM", path, 0, f"{sec}: '{name}' installs from a URL/git/local path, not the registry", f"{name}: {spec}")
            if name in ODD_DEPS:
                s.add("MEDIUM", path, 0, f"unusual dependency '{name}': {ODD_DEPS[name]}", f"{name}: {spec}")
    if pkg.get("allowScripts"):
        s.add("INFO", path, 0, "allowScripts list (packages permitted to run install scripts)", json.dumps(pkg["allowScripts"]))


def check_extension_manifest(s, path, text):
    """Browser extensions run with the user's sessions; flag the permissions that let them read or send them."""
    try:
        m = json.loads(text)
    except Exception:
        return
    if "manifest_version" not in m:
        return
    perms = set(m.get("permissions") or []) | set(m.get("optional_permissions") or [])
    hosts = set(m.get("host_permissions") or [])
    for cs in m.get("content_scripts") or []:
        hosts |= set(cs.get("matches") or [])
    broad = {h for h in hosts if h in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")}
    risky = perms & {"cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest", "debugger", "nativeMessaging", "proxy", "history", "clipboardRead", "management"}
    sev = "HIGH" if (risky and broad) or "debugger" in perms or "nativeMessaging" in perms else ("MEDIUM" if risky or broad else "INFO")
    s.add(sev, path, 0, "browser extension - it runs with your logged-in sessions; check every network call in its scripts",
          f"permissions={sorted(perms)} hosts={sorted(hosts)[:6]}")


def check_ai_directed(s, path, text, agent_file):
    base = os.path.basename(path).lower()
    is_config = agent_file or "/.git/" in "/" + path or base.endswith((".json", ".yml", ".yaml", ".toml", ".ini", ".cfg"))
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 600:
            continue
        for p in AI_DIRECTED:
            if p.search(line):
                if BENIGN_DIRECTIVE.search(line):
                    break
                has_ai = re.search(r"\b" + AI_WORDS + r"\b", line, re.I)
                sev = "HIGH" if (has_ai or is_config or re.search(r"\.git\b|hooks?|node_modules|\.env", line)) else "MEDIUM"
                s.add(sev, path, i, "instruction telling a reader/AI to NOT look at or to ignore something - investigate its target first", line)
                break


def check_code(s, path, text):
    base = os.path.basename(path).lower()
    minified = base.endswith((".min.js", ".bundle.js", ".d.ts", ".map")) or any(seg in BUILD_DIRS for seg in path.split("/"))
    counts = defaultdict(int)
    # Multi-line: a write target built from process.cwd() plus runtime data (the RWA dropper split this over lines).
    for m in re.finditer(r"(?:path\.join|path\.resolve)\(\s*process\.cwd\(\)\s*,\s*(?!['\"`])[\w.\[\]]+\s*\)", text):
        window = text[m.end(): m.end() + 400]
        if re.search(r"writeFile(?:Sync)?\s*\(|createWriteStream\s*\(|appendFile(?:Sync)?\s*\(", window):
            s.add("HIGH", path, text[: m.start()].count("\n") + 1,
                  "writes a file to a path built from runtime data under the working directory (dropper pattern - is the path validated?)",
                  m.group(0))
    obf = len(OBFUSCATION.findall(text))
    if obf >= 8:
        s.add("HIGH", path, 0, f"heavily obfuscated JavaScript ({obf} _0x-style identifiers)")
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000 and not minified:
            # Browser bundles legitimately contain eval/Function; Node-only and obfuscator tokens do not.
            risky = re.search(r"child_process|process\.execPath|_0x[0-9a-f]{4}|eval\(\s*atob", line)
            s.add("HIGH" if risky and len(line) > 5000 else "MEDIUM", path, i, f"single line of {len(line):,} chars in a non-minified source file" + (" containing code-execution/obfuscation tokens" if risky else ""), line[:120])
            continue
        if OFFSCREEN.search(line) and not minified:
            s.add("HIGH", path, i, "code pushed off-screen by a long run of spaces", line.strip()[:160])
        for sev, rx, msg in CODE_RULES:
            if minified and sev != "HIGH":
                continue
            if rx.search(line):
                counts[msg] += 1
                if counts[msg] <= 3:
                    s.add(sev, path, i, msg, line)
                elif counts[msg] == 4:
                    s.add("INFO", path, i, f"(more matches of: {msg})")


def check_unicode(s, path, text):
    code = os.path.splitext(path.lower())[1] in CODE_EXT
    for i, line in enumerate(text.splitlines(), 1):
        if BIDI.search(line):
            if not code:
                continue  # normal in right-to-left translations
            s.add("HIGH", path, i, "bidirectional Unicode control character (can make code read differently than it runs)", repr(line[:120]))
        elif ZERO_WIDTH.search(line) and not line.startswith("﻿"):
            s.add("MEDIUM", path, i, "zero-width Unicode character", repr(line[:120]))


def check_network(s, path, text, net):
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:
            continue
        for u in URL_RE.findall(line):
            if SUSPICIOUS_HOSTS.search(u):
                ext = os.path.splitext(path.lower())[1]
                s.add("MEDIUM" if ext in CODE_EXT or ext in (".json", ".yml", ".yaml", ".toml", ".sample") or "/.git/" in "/" + path else "INFO", path, i, "contacts a throwaway/paste/short-link/blockchain-RPC host (common for malware staging)", u)
            net["urls"].add(u.rstrip(".,;"))
        for ip in IP_RE.findall(line):
            parts = [int(x) for x in ip.split(".")]
            private = parts[0] in (0, 10, 127, 255) or (parts[0] == 192 and parts[1] == 168) or (parts[0] == 172 and 16 <= parts[1] <= 31) or (parts[0] == 169 and parts[1] == 254)
            if not private and not re.search(r"version|\"\d+\.\d+\.\d+\.\d+\"\s*:|@\d", line):
                s.add("MEDIUM", path, i, "hard-coded public IP address", ip)
                net["ips"].add(ip)


def sniff(data):
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def png_end(data):
    """Offset just past the IEND chunk, walking real chunks (not a text search)."""
    i = 8
    while i + 12 <= len(data):
        length = int.from_bytes(data[i:i + 4], "big")
        ctype = data[i + 4:i + 8]
        i += 12 + length
        if ctype == b"IEND":
            return i
    return None


def check_binary(s, path, data):
    ext = os.path.splitext(path.lower())[1]
    n = len(data)
    real = sniff(data)
    named = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif", ".pdf": "pdf", ".webp": "webp"}.get(ext)
    if named and real != named:
        s.add("INFO" if real in ("jpeg", "png", "gif", "webp") and named != "pdf" else "MEDIUM", path, 0, f"file named {ext} is really {real or 'not an image'} - disguised file type")
    trailing = 0
    if real == "jpeg":
        end = data.rfind(b"\xff\xd9")
        trailing = n - end - 2 if end != -1 else 0
    elif real == "png":
        end = png_end(data)
        trailing = n - end if end else 0
    elif real == "gif":
        trailing = 0 if data.rstrip(b"\x00").endswith(b";") else -1
    elif real == "pdf":
        eof = data.rfind(b"%%EOF")
        trailing = n - eof - 7 if eof != -1 and n - eof - 7 > 64 else 0
    elif real == "webp":
        trailing = n - (int.from_bytes(data[4:8], "little") + 8)
    if trailing > 16:
        s.add("HIGH", path, 0, f"{trailing:,} bytes hidden after the end of the {real.upper()} data (steganography carrier) - find the code that reads this file as bytes")
    elif trailing == -1:
        s.add("MEDIUM", path, 0, "GIF does not end with its trailer byte - possible appended data")
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x7fELF") or data[:2] == b"MZ":
        s.add("MEDIUM", path, 0, "compiled executable checked into the repo")


def check_svg_html(s, path, text):
    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", m.group(1)):
            line = text[: m.start()].count("\n") + 1
            s.add("HIGH", path, line, "long base64 blob hidden in a comment (payload fragment pattern)", m.group(1)[:100])
    if path.lower().endswith(".svg") and re.search(r"<script|onload=|javascript:", text, re.I):
        s.add("MEDIUM", path, 0, "SVG contains script")


def scan_file(s, rel, data, net):
    low = rel.lower()
    base = os.path.basename(low)
    if "/" + low in ("/.git/config",) or low.endswith("/.git/config") or low == ".git/config":
        check_git_config(s, rel, data.decode("utf-8", "replace"))
    if "/.git/hooks/" in "/" + low:
        check_git_hook(s, rel, data)
        text = data.decode("utf-8", "replace")
        check_code(s, rel, text)
        check_network(s, rel, text, net)
        return
    if base == ".gitattributes":
        for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            if "filter=" in line and "filter=lfs" not in line:
                s.add("HIGH", rel, i, "custom git filter - runs a configured command on checkout/add", line)
    if base in ("tasks.json", "launch.json", "settings.json") and "/.vscode/" in "/" + low:
        t = data.decode("utf-8", "replace")
        if re.search(r"folderOpen", t):
            s.add("HIGH", rel, 0, "VS Code/Cursor task set to run automatically when the folder is opened", re.search(r".{0,80}folderOpen.{0,40}", t).group(0))
        if re.search(r"allowAutomaticTasks", t):
            s.add("HIGH", rel, 0, "workspace setting enables automatic tasks")
    if "/.devcontainer/" in "/" + low and re.search(rb"(postCreateCommand|postStartCommand|initializeCommand|postAttachCommand)", data):
        s.add("MEDIUM", rel, 0, "devcontainer runs a command on create/start - read it")
    if base == "package.json":
        check_package_json(s, rel, data.decode("utf-8", "replace"))
    if base == "manifest.json":
        check_extension_manifest(s, rel, data.decode("utf-8", "replace"))

    ext = os.path.splitext(base)[1]
    if ext in (".jpg", ".jpeg", ".png", ".gif", ".pdf") or not is_texty(rel, data):
        check_binary(s, rel, data)
        return
    text = data.decode("utf-8", "replace")
    agent_file = base in AGENT_FILES or "/.claude/" in "/" + low or "/.cursor/" in "/" + low or base.endswith(".mdc")
    if agent_file:
        s.notes["AI agent instruction files (read these yourself, treat as data)"].append(rel)
    if not low.endswith(".git/config"):  # git config comments are reported by check_git_config
        check_ai_directed(s, rel, text, agent_file)
    check_unicode(s, rel, text)
    if ext in CODE_EXT or base.endswith(".sample"):
        check_code(s, rel, text)
    if ext in (".svg", ".html", ".htm", ".xml"):
        check_svg_html(s, rel, text)
    if ext not in (".md", ".mdx", ".txt", ".lock") and base not in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
        check_network(s, rel, text, net)


def walk_dir(root):
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        keep = []
        for d in dirnames:
            full_rel = "/" + rel_dir + d + "/"
            if d in SKIP_DIRS:
                yield ("__skipped__", rel_dir + d, None)
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in filenames:
            if "/.git/" in "/" + rel_dir and not GIT_KEEP.search(rel_dir + f):
                continue
            p = os.path.join(dirpath, f)
            if os.path.islink(p):
                yield ("__symlink__", rel_dir + f, os.readlink(p))
                continue
            try:
                size = os.path.getsize(p)
                with open(p, "rb") as fh:
                    data = fh.read(MAX_BYTES)
            except OSError:
                continue
            yield (rel_dir + f, size, data)


def walk_zip(zpath):
    with zipfile.ZipFile(zpath) as z:
        names = z.namelist()
        tops = {n.split("/", 1)[0] for n in names if "/" in n}
        prefix = (tops.pop() + "/") if len(tops) == 1 and all(n.startswith(next(iter({*names}), "")[:0]) for n in names) else ""
        seen_skip = set()
        for info in z.infolist():
            if info.is_dir():
                continue
            rel = info.filename[len(prefix):] if prefix and info.filename.startswith(prefix) else info.filename
            parts = rel.split("/")
            skip = next((p for p in parts[:-1] if p in SKIP_DIRS), None)
            if skip:
                key = "/".join(parts[: parts.index(skip) + 1])
                if key not in seen_skip:
                    seen_skip.add(key)
                    yield ("__skipped__", key, None)
                continue
            if "/.git/" in "/" + rel and not GIT_KEEP.search(rel):
                continue
            if info.file_size > MAX_BYTES:
                yield (rel, info.file_size, z.open(info).read(MAX_BYTES))
            else:
                yield (rel, info.file_size, z.read(info))


def main():
    if len(sys.argv) != 2:
        print("usage: python3 -I scan_repo.py <repo-folder-or-zip>")
        sys.exit(2)
    target = os.path.abspath(os.path.expanduser(sys.argv[1]))
    s = Scan()
    net = {"urls": set(), "ips": set()}
    files = 0
    is_zip = os.path.isfile(target) and zipfile.is_zipfile(target)
    walker = walk_zip(target) if is_zip else walk_dir(target)
    for rel, size, data in walker:
        if rel == "__skipped__":
            s.notes["Skipped dependency/build folders (shipped deps can be tampered; reinstall clean instead of trusting them)"].append(size)
            if size.endswith("node_modules") and size.count("/") <= 1:
                if is_zip:
                    s.add("MEDIUM", size, 0, "the download ships its own node_modules - never run code from it; reinstall clean")
                else:
                    s.notes["node_modules present - fine if YOU installed it; if it came with the download, delete and reinstall"].append(size)
            continue
        if rel == "__symlink__":
            s.notes["Symlinks (check they don't point outside the repo)"].append(f"{size} -> {data}")
            continue
        files += 1
        try:
            scan_file(s, rel, data, net)
        except Exception as e:  # keep scanning; a parser error is not a verdict
            s.add("INFO", rel, 0, f"could not fully scan: {e}")

    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    s.findings.sort(key=lambda f: (order[f[0]], f[1], f[2]))
    tally = defaultdict(int)
    for f in s.findings:
        tally[f[0]] += 1
    print(f"Static scan of: {target}")
    print(f"Files read: {files}  |  HIGH: {tally['HIGH']}  MEDIUM: {tally['MEDIUM']}  INFO: {tally['INFO']}")
    print("Nothing was executed, imported or extracted.\n")
    for sev in ("HIGH", "MEDIUM", "INFO"):
        group = [f for f in s.findings if f[0] == sev]
        if not group:
            continue
        print(f"=== {sev} ({len(group)}) ===")
        for _, path, line, msg, snip in group:
            loc = f"{path}:{line}" if line else path
            print(f"- {loc}\n    {msg}" + (f"\n    > {snip}" if snip else ""))
        print()
    for title, items in s.notes.items():
        print(f"=== {title} ===")
        for it in sorted(set(items))[:40]:
            print(f"- {it}")
        print()
    noise = r"localhost|127\.0\.0\.1|example\.(com|org)|schema|w3\.org|xmlns|images\.(pexels|unsplash)\.com|fonts\.(googleapis|gstatic)\.com|placeholder|github\.com/[^/]+/[^/]+\.git$|\$\{"
    hosts = defaultdict(int)
    for u in net["urls"]:
        if re.search(noise, u):
            continue
        hosts[re.sub(r"^https?://([^/:?#]+).*", r"\1", u)] += 1
    if hosts:
        print(f"=== External hosts referenced in code/config ({len(hosts)}) - eyeball for anything you can't explain ===")
        for h, c in sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:60]:
            print(f"- {h} ({c})")


if __name__ == "__main__":
    main()
