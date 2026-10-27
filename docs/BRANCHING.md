# Branching and review rules

- `main` is always runnable (`make up && make smoke` passes). Nobody pushes to it directly.
- Branch names: `p<N>/<short-topic>` (e.g. `p4/yolo-person-detect`). Keep branches under 2 days old.
- Commits: `feat:`, `fix:`, `docs:`, `chore:`, `test:` prefixes.
- PR rules: CI green, **1 approval**, squash merge. Review within 4 working hours (a blocked reviewer is a blocked team).
- Contract changes (`docs/CONTRACT.md`, `contract/`, `acl.conf`) require Person 1 as reviewer.
- Never commit `.env`, keys, certs, or video datasets (use a download script instead).

## GitHub settings to enable (Settings > Branches > Add rule for `main`)
Require pull request, require 1 approval, require status checks `lint-test` and `docker`, block force pushes.

> **Manual, owner-side steps before the team pushes:** enable the branch protection rule above
> (it cannot be committed), and replace the placeholder handles in `.github/CODEOWNERS` with real
> GitHub usernames/teams. Until then the `USER`@example.com owners are decorative.
