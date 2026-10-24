# Releasing rbic-plugin

Releases are built and published by `.github/workflows/release.yml` when a
tag `vX.Y.Z` is pushed. Publishing uses PyPI **Trusted Publishing**
(GitHub OIDC): no API tokens or repository secrets exist, and none should be
added. Each release goes to TestPyPI first, then to PyPI once the `pypi`
environment is approved.

The PyPI project name is `rbic-plugin` (import name `rbic`). The name is
claimed by the first successful upload, so do the one-time setup below
before pushing the first tag.

## One-time setup (repository owner)

### 1. GitHub environments

Repository → Settings → Environments → New environment:

- `testpypi` — no protection rules needed.
- `pypi` — recommended: **Required reviewers** = `mosesliao`, so every
  production upload waits for an explicit approval. Optionally restrict
  "Deployment branches and tags" to tags matching `v*.*.*`.

The names must match exactly; the workflow's `publish-testpypi` and
`publish-pypi` jobs refer to them.

### 2. Pending trusted publishers

The project doesn't exist on either index yet, so register a *pending*
publisher on each (account → Publishing → "Add a new pending publisher" →
GitHub):

| Field | test.pypi.org | pypi.org |
| --- | --- | --- |
| PyPI project name | `rbic-plugin` | `rbic-plugin` |
| Owner | `mosesliao` | `mosesliao` |
| Repository name | `rbic-plugin` | `rbic-plugin` |
| Workflow name | `release.yml` | `release.yml` |
| Environment name | `testpypi` | `pypi` |

A pending publisher becomes a normal trusted publisher on the first upload,
which also creates (claims) the project.

### 3. Protect release tags (recommended)

Repository → Settings → Rules → Rulesets → New tag ruleset:

- Target tags matching `v*`.
- Restrict creations, updates and deletions so only the owner (or a release
  team) can push them.

Anyone who can push a `v*` tag can start a release. The `pypi` environment
reviewer is the second gate.

## Cutting a release

1. Open a PR that bumps `__version__` in `src/rbic/__init__.py` (the only
   place the version lives), e.g. `0.1.0.dev0` → `0.1.0`. Merge it once the
   required `pytest (3.10)`, `pytest (3.11)` and `pytest (3.12)` checks pass.
2. Tag the merge commit on `main` and push the tag:

   ```bash
   git switch main && git pull --ff-only
   git tag -a v0.1.0 -m "rbic-plugin 0.1.0"
   git push origin v0.1.0
   ```

3. The `release` workflow runs:
   - `build`: checks that the tag equals `v` + `rbic.__version__` (it stops
     if they differ), runs the test suite, builds the sdist and wheel, and
     uploads them as the `dist` artifact.
   - `publish-testpypi`: uploads to TestPyPI.
   - `publish-pypi`: waits for approval of the `pypi` environment, then
     uploads the same files to PyPI.
4. Optionally check the TestPyPI upload before approving:

   ```bash
   python -m venv /tmp/rbic-check
   /tmp/rbic-check/bin/pip install --index-url https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ rbic-plugin==0.1.0
   /tmp/rbic-check/bin/python -c "import rbic; print(rbic.__version__)"
   ```

5. Approve the `pypi` deployment (Actions → the run → Review deployments).
6. Bump `__version__` to the next `.dev0` (e.g. `0.1.1.dev0`) in a follow-up
   PR.

## If something goes wrong

- **Tag/version mismatch**: delete the tag (`git push origin :refs/tags/vX.Y.Z`),
  fix `__version__` via a PR, and tag again.
- **A publish job failed**: if nothing was uploaded (e.g. a trusted
  publisher misconfiguration), fix the setup and re-run the failed job.
  An index never accepts the same file name twice, so if some files were
  already uploaded, release a new version instead.
- **A bad release**: yank it on PyPI (project → Manage → Releases → Yank)
  and release a fixed version. Don't delete releases.
