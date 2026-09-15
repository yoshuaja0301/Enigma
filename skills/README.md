# Skills

OpenClaw skills for this repository. Each subdirectory holds one `SKILL.md` plus
its `references/`, `scripts/`, `templates/` and `assets/`.

| Skill | Purpose |
| --- | --- |
| [`osstmm`](osstmm/SKILL.md) | Run an authorized OSSTMM 3 audit: scope and RoE, 5 channels x 17 modules, rav / Actual Security metrics, STAR report |

## Using them with OpenClaw

OpenClaw discovers skills from `SKILL.md` files under its skill roots, highest
precedence first:

1. `<workspace>/skills` — where these live, so opening this repository as the
   workspace is enough; nothing to install.
2. `<workspace>/.agents/skills`
3. `~/.agents/skills` — copy or symlink a skill here to use it from any workspace:
   `ln -s "$PWD/skills/osstmm" ~/.agents/skills/osstmm`
4. `<state-dir>/skills`, workshop skills, bundled skills, and
   `skills.load.extraDirs`.

The slash command comes from the frontmatter `name`, not the folder path, so
`osstmm` is invoked as `/osstmm` when `user-invocable: true`. The same layout is
read by Claude Code and other agents that follow the `SKILL.md` convention.

Verify a skill after editing it:

```
python3 skills/osstmm/scripts/rav.py --self-test
python3 skills/osstmm/scripts/checklist.py --channel all >/dev/null && echo ok
```
