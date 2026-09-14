Sub2API Plus v0.2.4-fork.2

## Highlights

- Fixes the fork release pipeline so the published asset set matches the upstream Plus line: per-platform archives, checksums, and the model-pricing JSON plus manifest that previously failed validation.
- Teaches the pricing manifest, update service, and release tooling the `vX.Y.Z-fork.N` tag format, so the fork line is self-consistent end to end.
- Repairs the fork's CI: the Codex fingerprint mode tests now assert the documented `off` default, and the unchecked type assertion in the prompt-cache-key test is resolved.
- Points every functional repository reference (installer, pricing manifest, self-update, compliance links, images) at `v2-share/sub2api-plus`.

## Changed

- Synchronizes README (EN/中文/日本語), UPSTREAM.md, deploy guides, Compose files, and example configuration to the fork repository and the `v0.2.4-fork.2` version.
- Publishes the fork release as the repository's `latest` release so the one-line installer can resolve it (the `-fork.N` suffix is a SemVer prerelease).
- Extends `tools/` release checks (`check_release`, `release_docs`, `release_finalization`, `release_preflight`, `check_new_migrations`) to accept both release lines.

## Fixed

- `pricing-manifest-build` no longer rejects `vX.Y.Z-fork.N`, which previously aborted the release at the pricing-asset step.
- The GitHub Actions `goreleaser-config` job no longer fails on the fork version format.
- GoReleaser's GHCR entries render even when the optional `SKIP_GHCR_IMAGES` variable is absent.

## Compatibility and migration

No new database migration is required and no configuration change is required for existing deployments. Operators upgrading from `v0.2.4-fork.1` should switch to the `v0.2.4-fork.2` GHCR tag or archive; `v0.2.4-fork.1` remains published for rollback.

## Known issues

The `backend/repository.test` fixture from historical history remains in the repository and inflates clone size; it does not affect builds or releases.

## Upstream baseline

Official release: v0.2.4
Official commit: 5de5e2bed035d43591a2e10e51f420ef6a84eb98
