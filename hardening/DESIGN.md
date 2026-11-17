# Hardened fork: release pipeline design

## Goal

Keep taking features from upstream (pingdotgg/t3code) while guaranteeing that every release
of this fork has been evaluated for code that sends data anywhere other than the agent
providers. When speed and safety conflict, safety wins: a hardened release never ships
without a human approving it.

## Branches

| Branch | Contents | Who writes it |
|---|---|---|
| `main` | Exact mirror of upstream `main` | The sync workflow only (fast-forward) |
| `hardened` (default) | Upstream stable release + this fork's hardening changes | Pull requests only, after evaluation |
| `candidate/vX.Y.Z` | `hardened` with upstream tag `vX.Y.Z` merged in | The sync workflow |

`hardening/UPSTREAM_VERSION` on `hardened` records the upstream tag it was last evaluated
against. Upstream stable tags are the unit of evaluation; nightlies are never merged.

## Pipeline

```
upstream tag vX ──► sync ──► candidate/vX ──► PR into hardened
                                               │
                     ┌─────────────────────────┤
                     ▼                         ▼
              gate (no secrets)        review (Claude, diff only)
                     │                         │
                     └──────────► human approval (CODEOWNERS) ──► merge ──► release (phase 2)
```

1. **Sync** (`hardened-sync.yml`, every 6 hours). Fast-forwards `main`. When a new stable
   tag appears, merges it into a `candidate/` branch, strips upstream workflows, restores
   this fork's own files, and opens a PR. A merge conflict outside upstream workflows stops
   the run and opens an issue; conflicts are always resolved by a person.
2. **Gate** (`hardened-evaluate.yml`, job `gate`). Deterministic checks over the whole
   upstream delta between the old and new tags. It has no secrets and never runs repo code.
   Any finding fails the check until it is fixed or accepted (below).
3. **Review** (job `review`). Claude reads the riskiest parts of the delta and reports
   findings. It is triage: it can miss things and can be steered by text in upstream code,
   so it never approves anything. High-severity findings fail the check.
4. **Human approval.** Branch protection on `hardened` requires both checks and a review
   from CODEOWNERS. No auto-merge.
5. **Release** (phase 2). Built only from a merged `hardened` commit, behind a protected
   environment that needs approval, with SBOM, build provenance and the evaluation report.

## What the gate checks

| Check | Finding id | Fails when |
|---|---|---|
| New network hosts | `host:<name>` | A hostname appears in code at the new tag that was not in code at the old tag and is not in `egress-allowlist.txt` |
| Sensitive patterns | `pattern:<rule>:<file>` | An added line matches a rule in `sensitive-patterns.txt` (telemetry SDKs, relay, tunnels, raw sockets) |
| New dependencies | `dep:<name>@<version>` | A package is added to `pnpm-lock.yaml` |
| Install scripts | `install-script:<file>` | A `preinstall`, `install` or `postinstall` script is added to a `package.json` |
| Binary files | `binary:<file>` | A binary file is added or changed outside image and font assets |
| Fork-owned paths | `owned-path:<file>` | Upstream touches `.github/`, `hardening/` or `scripts/hardening/` |

A finding is resolved by changing the code, or by adding its id to `accepted-findings.txt`
with a reason, in the same PR. That file is CODEOWNERS-protected, so every acceptance is a
reviewed decision on the record.

## Pipeline security

- Upstream code is untrusted. No job that holds a secret runs, installs or builds it.
- The gate and review scripts always run from the base branch (`hardened`), never from the
  PR, so an upstream change cannot rewrite the checks that evaluate it.
- Upstream workflows are deleted on every merge; only `hardened-*` workflows run.
- Third-party actions are pinned to full commit SHAs.
- The sync job uses a GitHub App token scoped to this repo (contents, pull requests,
  workflows, issues), not a personal token.

## One-time setup

1. Create a GitHub App owned by your account with repository permissions: Contents (write),
   Pull requests (write), Issues (write), Workflows (write). Install it on this repo only.
2. Add repo secrets `HARDEN_APP_ID`, `HARDEN_APP_PRIVATE_KEY`, `ANTHROPIC_API_KEY`.
3. Make `hardened` the default branch (scheduled workflows run from the default branch).
4. Protect `hardened`: require PRs, require review from code owners, require status checks
   `gate` and `review`, block force pushes, include administrators.
5. Protect `main`: only the sync App may push; block force pushes.

## Phase 2 (not built yet)

- **Live network test.** Build the candidate in a job with no secrets and egress recorded
  (for example an egress-auditing proxy), run a scripted agent session against a stub
  provider, and fail on any connection outside the allowlist.
- **Release workflow.** Protected `hardened-release` environment with required reviewers;
  builds from the merged commit; publishes checksums, SBOM and
  `actions/attest-build-provenance` attestations; attaches the gate and review reports.
- **Build-time feature removal** of T3 Connect and telemetry modules, plus an in-app egress
  allowlist, so a missed upstream change still cannot connect out.
