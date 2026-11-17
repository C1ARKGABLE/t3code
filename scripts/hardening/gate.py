#!/usr/bin/env python3
"""Deterministic security gate for an upstream delta.

Compares two git revisions of the repository under test and reports changes that need a
human decision: new network hosts, sensitive code patterns, new dependencies, install
scripts, binaries, and changes to paths this fork owns. Reads git only; never runs code
from the repository under test.

Exit status: 0 = no unaccepted findings, 1 = unaccepted findings, 2 = error.
"""

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

CODE_GLOBS = [
    "*.ts", "*.tsx", "*.js", "*.mjs", "*.cjs", "*.jsx", "*.json", "*.rs", "*.go", "*.py",
    "*.sh", "*.yml", "*.yaml", "*.toml", "*.swift", "*.kt", "*.html", "*.vue",
]
EXCLUDE_GLOBS = [
    "*.md", "*.mdx", "docs/*", "*/docs/*", "*.test.*", "*.spec.*", "*/__tests__/*",
    "*/test/*", "*/tests/*", "*/fixtures/*", "*/__fixtures__/*", "*.snap", "pnpm-lock.yaml",
    "third-party-licenses/*", "*/third-party-licenses/*", ".github/workflows/*", "evals/*",
]
ASSET_GLOBS = [
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.svg", "*.ico", "*.icns", "*.avif",
    "*.woff", "*.woff2", "*.ttf", "*.otf",
]
OWNED_PATHS = ["hardening/", "scripts/hardening/", ".github/CODEOWNERS"]

URL_RE = re.compile(r"\b(?:https?|wss?)://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", re.I)
LOCK_PKG_RE = re.compile(r"^  '?(@?[^@\s'(]+)@([^:'\s(]+)(?:\([^']*\))?'?:\s*$")
INSTALL_SCRIPT_RE = re.compile(r'"(?:pre|post)?install"\s*:')
IGNORED_HOSTS = {"localhost", "example.com", "example.org", "example.net"}


def git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo)] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("git %s failed: %s" % (" ".join(args), result.stderr.decode()))
    return result.stdout.decode("utf-8", "replace")


def matches(path, globs):
    return any(fnmatch.fnmatch(path, g) for g in globs)


OUT_OF_SCOPE = []


def in_scope(path):
    return not path.startswith(tuple(OUT_OF_SCOPE)) if OUT_OF_SCOPE else True


def is_code(path):
    return matches(path, CODE_GLOBS) and not matches(path, EXCLUDE_GLOBS) and in_scope(path)


def lock_names(repo, rev):
    names = set()
    for line in git(repo, "show", rev + ":pnpm-lock.yaml").splitlines():
        m = LOCK_PKG_RE.match(line)
        if m:
            names.add(m.group(1))
    return names


def load_lines(path):
    if not path.exists():
        return []
    out = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def host_allowed(host, allowlist):
    host = host.lower().rstrip(".")
    if host in IGNORED_HOSTS or host.endswith(".localhost") or host.endswith(".test"):
        return True
    for entry in allowlist:
        entry = entry.lower()
        if entry.startswith("*.") and (host == entry[2:] or host.endswith(entry[1:])):
            return True
        if host == entry:
            return True
    return False


def hosts_at(repo, rev):
    out = git(repo, "grep", "-I", "-o", "-E", r"(https?|wss?)://[A-Za-z0-9.-]+", rev, "--", ".")
    hosts = set()
    for line in out.splitlines():
        # format: rev:path:match
        parts = line.split(":", 2)
        if len(parts) < 3 or not is_code(parts[1]):
            continue
        for host in URL_RE.findall(parts[2]):
            hosts.add(host.lower().rstrip("."))
    return hosts


def added_lines(repo, base, head, pathspec=None):
    args = ["diff", "-U0", "--no-color", "--no-ext-diff", base, head]
    if pathspec:
        args += ["--"] + pathspec
    current = None
    for line in git(repo, *args).splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and current is not None:
            yield current, line[1:]


def load_patterns(path):
    rules = []
    for line in load_lines(path):
        name, _, regex = line.partition("=")
        rules.append((name.strip(), re.compile(regex.strip(), re.I)))
    return rules


def evaluate(repo, base, head, config):
    OUT_OF_SCOPE[:] = load_lines(config / "out-of-scope-paths.txt")
    findings = {}

    def add(fid, kind, detail):
        findings.setdefault(fid, {"id": fid, "kind": kind, "details": []})
        if len(findings[fid]["details"]) < 5:
            findings[fid]["details"].append(detail)

    allowlist = load_lines(config / "egress-allowlist.txt")
    new_hosts = hosts_at(repo, head) - hosts_at(repo, base)
    for host in sorted(new_hosts):
        if not host_allowed(host, allowlist):
            add("host:" + host, "New network host", "first seen in code at " + head)

    rules = load_patterns(config / "sensitive-patterns.txt")
    for path, text in added_lines(repo, base, head):
        if path.startswith(tuple(OWNED_PATHS)):
            continue
        if path.endswith("package.json") and INSTALL_SCRIPT_RE.search(text):
            add("install-script:" + path, "Install script", text.strip()[:160])
        if not is_code(path):
            continue
        for name, regex in rules:
            if regex.search(text):
                add("pattern:%s:%s" % (name, path), "Sensitive pattern: " + name, text.strip()[:160])

    known = lock_names(repo, base)
    bumps = set()
    for _, text in added_lines(repo, base, head, ["pnpm-lock.yaml"]):
        m = LOCK_PKG_RE.match(text)
        if not m:
            continue
        if m.group(1) in known:
            bumps.add("%s@%s" % (m.group(1), m.group(2)))
        else:
            add("dep:%s@%s" % (m.group(1), m.group(2)), "New dependency", "package not in lock at " + base)

    for line in git(repo, "diff", "--numstat", base, head).splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] == "-" and in_scope(parts[2]) \
                and not matches(parts[2], ASSET_GLOBS):
            add("binary:" + parts[2], "Binary file", "added or changed")

    owned = git(repo, "diff", "--name-only", base, head, "--", *OWNED_PATHS)
    for path in owned.splitlines():
        add("owned-path:" + path, "Change to a fork-owned path", "upstream touched " + path)

    accepted = set(load_lines(config / "accepted-findings.txt"))
    result = sorted(findings.values(), key=lambda f: f["id"])
    for f in result:
        f["accepted"] = f["id"] in accepted
    return result, sorted(bumps)


def write_markdown(findings, bumps, base, head, path):
    open_ = [f for f in findings if not f["accepted"]]
    done = [f for f in findings if f["accepted"]]
    lines = ["## Hardening gate: `%s` → `%s`" % (base, head), ""]
    if not open_:
        lines.append("No unaccepted findings.")
    else:
        lines.append("**%d unaccepted finding(s).** Fix each one, or add its id to "
                     "`hardening/accepted-findings.txt` with a reason." % len(open_))
    for title, group in (("Unaccepted", open_), ("Accepted", done)):
        if not group:
            continue
        lines += ["", "### %s" % title, "", "| Id | Kind | Detail |", "|---|---|---|"]
        for f in group:
            detail = "<br>".join(d.replace("|", "\\|").replace("`", "'") for d in f["details"])
            lines.append("| `%s` | %s | %s |" % (f["id"], f["kind"], detail))
    if bumps:
        lines += ["", "<details><summary>%d dependency version change(s) (not blocking)</summary>"
                  % len(bumps), ""] + ["- `%s`" % b for b in bumps] + ["", "</details>"]
    Path(path).write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="repository under test")
    parser.add_argument("--base", required=True, help="old revision (for example v0.1.9)")
    parser.add_argument("--head", required=True, help="new revision (for example v0.1.10)")
    parser.add_argument("--config", required=True, help="trusted hardening/ directory")
    parser.add_argument("--report-md", required=True)
    parser.add_argument("--report-json", required=True)
    args = parser.parse_args()
    try:
        findings, bumps = evaluate(Path(args.repo), args.base, args.head, Path(args.config))
    except RuntimeError as err:
        print(err, file=sys.stderr)
        return 2
    write_markdown(findings, bumps, args.base, args.head, args.report_md)
    Path(args.report_json).write_text(
        json.dumps({"findings": findings, "version_changes": bumps}, indent=2) + "\n")
    unaccepted = sum(1 for f in findings if not f["accepted"])
    print("%d finding(s), %d unaccepted" % (len(findings), unaccepted))
    return 1 if unaccepted else 0


if __name__ == "__main__":
    sys.exit(main())
