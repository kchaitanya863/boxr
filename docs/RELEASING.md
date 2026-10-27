# Releasing boxr

How the automated release pipeline works, why the `RELEASE_TOKEN` secret exists,
and what to do when the secret goes stale.

## How the automated release works

Releases are fully automatic. Merging a PR to `main` is the only trigger you need.

1. A push to `main` (for example, a merged PR) triggers the `CI & Automated Release`
   workflow (`.github/workflows/ci.yml`).
2. The `test` job (`Test & Lint (macOS Self-Hosted)` — legacy check name) runs on
   **GitHub-hosted Ubuntu** with rootless deps (`uidmap`, `passt`): `cargo fmt --check`,
   clippy, the full test suite, Podman parity audit/blackbox, and shell black-box QA.
3. If tests pass, the `bump-and-tag` job (`Bump Version & Create Git Tag`) runs:
   - Checks out `main` with full history.
   - Computes the next version: takes the highest existing `v*` tag and increments
     the patch number.
   - Updates `version = ` in `Cargo.toml`, commits
     `chore(release): bump version to vX.Y.Z [skip ci]`, pushes to `main`,
     creates the annotated tag `vX.Y.Z`, and pushes the tag.
   - The `[skip ci]` in the commit message keeps the bump commit from re-triggering
     the pipeline; the tag push is what triggers the release jobs.
4. The `release` job (`Build & Publish Release`) builds binaries for macOS
   (arm64, x86_64), Linux musl (arm64, x86_64), and Windows (x86_64), packages the
   tarballs/zips plus `.deb`/`.rpm` packages, and publishes the GitHub release
   with generated release notes.
5. The `update-brew-tap` job (`Publish Release & Update Homebrew Tap`) uploads the
   assets to the `homebrew-tap` repo release and rewrites `Formula/boxr.rb` with
   the new tag and SHA256 checksums.

## Why RELEASE_TOKEN exists

The `main` branch is protected by a branch ruleset. The only bypass actor on that
ruleset is the repo owner (`kchaitanya863`). The default `GITHUB_TOKEN` that
GitHub Actions provides acts as `github-actions[bot]`, which is NOT a bypass
actor, so the bump job's `git push origin main` is rejected by the branch policy.

`RELEASE_TOKEN` is a token that lets the bump job push as the repo owner, who is a
bypass actor. The checkout step in the `bump-and-tag` job uses it like this:

```yaml
token: ${{ secrets.RELEASE_TOKEN || secrets.GITHUB_TOKEN }}
```

Token facts:

- Value: the repo owner's GitHub CLI OAuth token (from `gh auth login` on the
  release workstation). It authenticates as `kchaitanya863`, who is a bypass
  actor on the `main` branch ruleset.
- Scope: the token carries `repo` scope (plus `gist` and `read:org`), which is
  broader than strictly necessary. In practice only the `bump-and-tag` job ever
  sees it, and only that job's checkout step uses it.
- Lifetime: no fixed expiry. It stays valid until the CLI login is revoked or
  redone. If `gh auth` is ever refreshed on the workstation, re-set the secret
  (see below).
- Stored as: the `RELEASE_TOKEN` Actions secret on the boxr repo
  (Settings > Secrets and variables > Actions)

## Refreshing the secret (only needed if the CLI login changes)

The secret holds a copy of the workstation's `gh` login token. If that login is
ever revoked or redone (`gh auth login` / `gh auth refresh`), the copy goes
stale and the bump job starts failing. Refresh it with one command from any
machine logged in as the repo owner:

    gh auth token | gh secret set RELEASE_TOKEN --repo kchaitanya863/boxr

Then verify: the next push to `main` should show a green
`Bump Version & Create Git Tag` run followed by a new release. You can also
trigger the workflow manually from the Actions tab (the workflow has
`workflow_dispatch`).

To switch to a scoped fine-grained PAT later instead, generate one (GitHub
Settings > Developer settings > Fine-grained tokens: name `boxr-release`,
1-year expiry, only the `boxr` repo, Contents read and write) and store it as
`RELEASE_TOKEN` with the same command, replacing `gh auth token` with the PAT
value. Note the expiry date at the bottom of this file and rotate it yearly.

## How to recognize a stale or missing secret

- The `bump-and-tag` job fails immediately at its first step
  (`Verify RELEASE_TOKEN secret`) with:
  - `::error::RELEASE_TOKEN secret is missing or expired. The automated version bump cannot push to main without it.`
  - `::error::Rotation runbook: docs/RELEASING.md`
- If the guard is ever bypassed, the `git push` fails with a 403 and the job ends
  with:
  - `::error::Version-bump push to main failed. Most likely cause: RELEASE_TOKEN expired, revoked, or missing.`
  - `::error::Rotation runbook: docs/RELEASING.md`
- From the outside, the symptom is: merges to `main` stop producing new releases.
  The `Test & Lint` job stays green while `Bump Version & Create Git Tag` fails.

## Manual fallback

If the automation cannot push (for example, the token expired and no replacement
is ready yet), cut the release by hand. The repo owner is a bypass actor on
`main`, so pushing directly works:

1. `git checkout main && git pull`
2. Compute the next version: take the highest `v*` tag and increment the patch
   number. Update `version = ` in `Cargo.toml` to match.
3. `git commit -am "chore(release): bump version to vX.Y.Z [skip ci]" && git push origin main`
4. `git tag -a vX.Y.Z -m "Release vX.Y.Z" && git push origin vX.Y.Z`
5. The tag push triggers the `release` and `update-brew-tap` jobs automatically.
   Watch the Actions run to confirm the GitHub release and the formula update.

---

Secret last set: 2026-09-26, from the workstation `gh` login (no fixed expiry; re-set it if that login is ever revoked or redone).
