# CordClaw Publishing Guide

This document tracks release commands and required artifacts for:

- npm package: `@cordum/cordclaw`
- daemon binaries: GitHub Releases
- Homebrew tap formula
- Docker image: `ghcr.io/cordum-io/cordclaw-daemon`

## 1. Prepare Release

1. Update version values:
   - `plugin/package.json`
   - `pack/pack.yaml` metadata version
   - `packaging/homebrew/cordclaw-daemon.rb` version
2. Build and verify:
   - `cd daemon && make test && make release`
   - `cd plugin && npm ci && npm test && npm run build`
3. Run pack validation:
   - `cordumctl pack install ./pack --upgrade`
   - `cordumctl pack verify cordclaw`

## 2. Publish npm Package

```bash
cd plugin
npm publish --access public
```

## 3. Publish Daemon Binaries to GitHub Release

Expected artifacts from `daemon/bin/`:

- `cordclaw-daemon-linux-amd64`
- `cordclaw-daemon-linux-arm64`
- `cordclaw-daemon-darwin-amd64`
- `cordclaw-daemon-darwin-arm64`
- `cordclaw-daemon-windows-amd64.exe`

Attach these binaries to a tag release `vX.Y.Z`.

## 4. Publish Docker Image

```bash
docker build -f daemon/Dockerfile -t ghcr.io/cordum-io/cordclaw-daemon:vX.Y.Z daemon
docker tag ghcr.io/cordum-io/cordclaw-daemon:vX.Y.Z ghcr.io/cordum-io/cordclaw-daemon:latest
docker push ghcr.io/cordum-io/cordclaw-daemon:vX.Y.Z
docker push ghcr.io/cordum-io/cordclaw-daemon:latest
```

## 5. Update Homebrew Tap

1. Compute sha256 checksums for each release binary.
2. Replace placeholders in `packaging/homebrew/cordclaw-daemon.rb`.
3. Copy the formula into the tap repo:
   - `cordum-io/homebrew-tap/Formula/cordclaw-daemon.rb`
4. Open PR in tap repo and merge after CI passes.

## 6. Post-Release Verification

1. `npm view @cordum/cordclaw version`
2. `docker pull ghcr.io/cordum-io/cordclaw-daemon:latest`
3. `brew install cordum-io/tap/cordclaw-daemon`
4. `cordclaw-daemon --help`
