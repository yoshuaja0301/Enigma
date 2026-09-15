# Enigma
Evidence-based Web Vulnerability Verification Framework for AI-Assisted Security Assessment

## Packages

### `packages/enigma-pentest` — OpenClaw plugin

A native [OpenClaw](https://openclaw.org) plugin that provides a scope-enforced,
evidence-first pentest agent: 10 engagement modes with auto-detection, a
security-tools catalog, mode → skill → tool orchestration, and a `fullscan`
engagement flow. It is a port/adaptation of
[`zakirkun/oh-my-open-pentest`](https://github.com/zakirkun/oh-my-open-pentest)
(an OpenCode plugin) to OpenClaw's plugin SDK, with a **real runtime scope gate**
in place of the upstream's prompt-only model.

See [`packages/enigma-pentest/README.md`](packages/enigma-pentest/README.md) to
build, install, and configure it, and
[`packages/enigma-pentest/PORT-NOTES.md`](packages/enigma-pentest/PORT-NOTES.md)
for what was ported and the deliberate deviations.

> ⚠️ For authorized security assessment only — your own or explicitly consented
> targets, in-scope bug-bounty assets, CTF, or research. The plugin enforces
> explicit-engagement and target-scope gating by default.
