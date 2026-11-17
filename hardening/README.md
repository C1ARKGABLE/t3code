# Hardening

This fork keeps `main` as an unmodified mirror of
[pingdotgg/t3code](https://github.com/pingdotgg/t3code). Hardening work lives on the
`hardened` branch.

Releases from this fork have not been evaluated yet. Do not treat any build as reviewed.

## Reference policy

[`policy.json`](./policy.json) is a T3 Code
[managed policy](../docs/user/managed-policy.md) for running agents on machines that hold
sensitive code. It:

- allows clients over a private network (for example a tailnet), and turns off T3 Connect
- turns off product usage data and relay traces
- caps the permission mode at auto-accept edits, and defaults new threads to Supervised
- allows only the Claude and Codex providers, pinned to absolute binary paths
- turns off the agent browser, browser cookie import, and webhook tasks
- turns off update checks and the nightly channel

Before deploying it:

1. Set `organization` to your organization's name.
2. Point each `binaryPath` at a root-owned copy of that CLI. A path the user can write to
   lets them swap the binary.
3. Run `t3 policy check hardening/policy.json`, then install it at the path for your OS (on
   Linux, `/etc/t3code/policy.json`, root-owned and not writable by users).
4. Restart T3 Code and confirm with `t3 policy show`.

## Remote access

Expose the server through Tailscale Serve rather than `--lan`. With Tailscale Serve, the
server listens only on loopback and the tailnet's access rules decide who can reach it.
`--lan` also listens on the local network, and then a pairing code is the only lock.

Tailscale HTTPS certificates come from a public certificate authority, so each machine's
`*.ts.net` name shows up in public Certificate Transparency logs.

## What the policy does not cover

The policy is enforced by T3 Code itself, running as the user. It does not stop someone who
edits or replaces T3 Code, and it does not restrict the provider CLIs when they run outside
T3 Code. Use each CLI's own managed settings and your device management tool for those.

The hosted web app at app.t3.codes and the published mobile apps are built and served
upstream and send their own diagnostics. Use clients built from this fork instead.
