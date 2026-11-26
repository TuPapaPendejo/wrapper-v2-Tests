# Wrapper v2

**Self-hosted Apple Music playback and Temari-compatible context server.**

Wrapper v2 exposes an HTTP API for authenticated Apple Music sessions, playback data, and decryption contexts consumed by compatible clients such as [Gamdl](https://github.com/glomatico/gamdl). Version 1.0.0 uses a Rust HTTP supervisor and a native C++ worker.

The server does **not** download or decrypt media. Decryption is performed by the client. The legacy `/decrypt` endpoint is not part of the 1.0.0 API.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Current validation status

- **x86_64:** clean Docker installation, fresh Apple Account login, 2FA, session credentials, worker recycle/session recovery, playback, and `/key` HTTP requests were exercised successfully with Apple Music 3.6.0-beta, build 1109.
- **ARM64:** architecture-specific profiles and native code are present, but this change has not been validated through a complete live ARM64 build, login, playback, and context run. Treat ARM64 as unverified for this change.
- The device-fingerprint correction follows the combined configuration reported in [issue #23](https://github.com/glomatico/wrapper-v2/issues/23). The report changed the client tuple and Android ID length together; it did not isolate their individual effects.

Detailed source findings and sanitized x86_64 evidence are in [the source audit](docs/source-audit-2026-11.md).

## Features

- Temari-compatible playback and context API.
- Session login, 2FA, cached-session restore, and optional automatic login.
- Bounded worker supervision, recycling, and session recovery.
- Separate native workers and context-capture profiles for x86_64 and ARM64.
- Persistent device identity and session storage.
- Structured JSON logs with sanitized request metadata.
- Optional HTTP Bearer authentication for direct API clients.
- Optional idle expiry for abandoned two-factor challenges.
- Private Docker image build with architecture-specific Android runtime files and verified Apple native-library inputs.

## Requirements

| Component | Requirement |
| --- | --- |
| Host | Linux, x86_64 or aarch64 |
| Deployment | Docker Engine, Docker Compose plugin 2.24+, Buildx/BuildKit |
| Build input | An authorized local Apple Music 3.6.0-beta, build 1109 package for the target ABI; standalone APK or supported split APKM |
| Host tools | Git, Bash, coreutils, curl |
| Build toolchains | Android NDK r23b, Rust 1.100.0, CMake, Ninja, and cross-compilers are installed inside Docker |

The package version, manifests, architecture, and required Apple native libraries are pinned in the profiles. The build accepts a local package path; this repository does not provide the Apple Music package or direct users to a download source.

**Verification boundary:** the build helper calculates the SHA-256 of the supplied package and passes it to BuildKit to keep the input consistent during the build. This is not a trusted, pre-pinned checksum of the original APK/APKM archive. Compatibility is checked using the expected Android manifests and the SHA-256 hashes of the extracted native libraries in the selected profile.

## Quick start

Use a source revision containing the device-identity correction. The full procedure, including the current branch to use while the upstream pull request is pending, is in [docs/clean-install-linux.md](docs/clean-install-linux.md).

From the repository root, provide the path to your locally held, authorized Apple Music build 1109 package:

```bash
./tools/build-docker.sh "/absolute/path/to/your/AppleMusic-build-1109.apk" --arch x86_64
docker compose up -d
docker compose ps
```

The build helper also accepts a supported `.apkm` split bundle. The tested live path is x86_64; the ARM64 build command is documented in the runbook but has not been validated end to end in the reproduction recorded here.

Check the local service:

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/info
curl -fsS http://127.0.0.1:8080/session
```

Compose binds the HTTP service to loopback on port 8080 by default and stores account state in the persistent `wrapper_data` volume. No `.env` file is required for a normal fresh installation.

### Device identity and existing installations

A new installation generates a random 64-bit Android ID and persists the complete device identity in the session volume. The identity is reused across restarts and image rebuilds.

Existing `.wrapper-device-info` identities are not rewritten or migrated. The identity is paired with the native `.worker-device` hash and cached session state. Preserve the original session volume and, for legacy deployments, the existing `WRAPPER_DEVICE_INFO` and `WRAPPER_DATA_DIR` settings. Do not switch a legacy bind mount to the default named volume without migrating the data.

**Do not run `docker compose down -v` unless deleting the identity and cached session is intentional.**

## HTTP API

The 1.0.0 HTTP API is unversioned. Requests and responses use JSON; the native-worker IPC protocol is separate.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | HTTP liveness |
| `GET` | `/info` | Version, features, profile, and architecture |
| `GET` | `/session` | Session state and operation count |
| `GET` | `/session/credentials` | Export session credentials to a compatible client |
| `POST` | `/session/restore` | Restore a cached session |
| `POST` | `/session/login` | Start login with `username` and `password` |
| `GET` | `/session/challenge` | Retrieve the pending 2FA challenge |
| `POST` | `/session/challenge` | Submit `challenge_id` and six-digit `code`; empty code cancels |
| `POST` | `/session/close` | Close the session |
| `GET` | `/playback?adam_id=...` | Retrieve playback data |
| `GET` | `/context?adam_id=...&key_uri=...` | Retrieve a Temari-compatible context |
| `GET` | `/key?adamId=...&uri=...` | Compatibility alias for `/context` |

Playback and context requests are serialized through a single native worker. Concurrent requests may receive `503 worker_busy`. Eligible requests are retried internally after planned worker recycling.

### Optional API authentication

For direct HTTP clients, set `WRAPPER_API_TOKEN` in the private `.env` file. Generate a high-entropy value, for example:

```bash
openssl rand -hex 32
```

When configured, every route except `GET /health` requires an `Authorization: Bearer <token>` header. A missing or invalid token receives HTTP 401. When the variable is absent, the previous 1.0.0 API behavior is preserved. The token is loaded from the container environment, so users with Docker daemon access or permission to inspect the container can retrieve it; keep `.env` and Docker access restricted.

Do not enable this option for a Gamdl deployment unless the installed client/provider is known to send the Bearer header to all protected routes. The default loopback-only deployment remains compatible without it. A Bearer token does not encrypt traffic; use TLS through an authenticated reverse proxy for remote access.

### Optional 2FA idle timeout

`WRAPPER_2FA_TIMEOUT_SECONDS` sets the maximum time to wait for a human challenge response. It accepts `1` through `86400` seconds. An absent value or `0` preserves the previous indefinite wait. For example:

```dotenv
WRAPPER_2FA_TIMEOUT_SECONDS=900
```

When the deadline expires, the pending challenge is cleared and the native worker is discarded so another login can start. Choose a value longer than the expected user interaction window; avoid a short value when using slow or remote 2FA approval.

## Security and operations

**Do not expose the HTTP API directly to the Internet.** TLS is not built in. Unless `WRAPPER_API_TOKEN` is configured, the API also has no application-level authentication; `GET /session/credentials` returns sensitive session material. Keep the loopback binding, restrict Docker daemon access, and place deliberate remote access behind an authenticated TLS gateway.

The container runs the HTTP process as a non-root UID, with a read-only filesystem and an init process. The native launcher temporarily requires `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT` for namespaces, mounts, and chroot. The Compose profile also relaxes AppArmor; this is a deployment security trade-off documented by the current configuration and should not be copied into a more restrictive production policy without testing.

The locally built image contains extracted proprietary Apple libraries. Keep it private; do not publish or redistribute it without the necessary rights. Do not commit the package, extracted libraries, `.env`, credentials, logs containing session data, or the session volume.

See [docs/logging.md](docs/logging.md) for log fields and redaction, and [docs/worker-launch.md](docs/worker-launch.md) for namespace and worker lifecycle details.

## Development and tests

Run the source-level test suite from the repository root:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cmake -S . -B build/ci-native -DWORKER_ARCH=x86_64
cmake --build build/ci-native --target common_tests worker-launch --parallel 2
ctest --test-dir build/ci-native --output-on-failure
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

HTTP and supervisor integration tests use a synthetic worker; they do not exercise Apple's proprietary authentication path. The native C++ CI step exercises the shared protocol and launcher tests, not the Apple-specific Android binary. Linux namespace tests require `unshare` and the relevant kernel permissions. GitHub Actions also pins the Rust toolchain and third-party action revisions. Fork repositories may need Actions enabled manually; this workflow supports both pushes to `audit/security-hardening` and manual dispatch so the draft branch can be tested without making its PR ready for review. Passing synthetic checks does not replace a live test against the pinned Apple Music build.

Optional native-only developer workflows are available through `tools/build.sh` and `tools/build-local.sh`; they require their documented toolchains and are not necessary for the Docker build.

## Project documentation

- [Clean Linux installation runbook](docs/clean-install-linux.md)
- [Source audit, findings, and x86_64 validation evidence](docs/source-audit-2026-11.md)
- [Structured logging](docs/logging.md)
- [Native worker lifecycle](docs/worker-launch.md)
- [Changelog](CHANGELOG.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Acknowledgements

- **[zhaarey/wrapper](https://github.com/zhaarey/wrapper)** — the original Wrapper project.
- **[WorldObservationLog](https://github.com/WorldObservationLog)** — Wrapper Lite, Temari, and related research.
- **[@rocketguedes](https://github.com/rocketguedes)** — the diagnostic lead in [issue #23](https://github.com/glomatico/wrapper-v2/issues/23) that identified a device fingerprint configuration which completed fresh login and 2FA in the reported environment.

These acknowledgements recognize prior research and diagnostic contributions; they do not imply endorsement by the upstream authors.

## AI usage

This project received substantial assistance from AI coding tools for implementation, architecture discussion, debugging, testing, and documentation. AI-generated output can be incorrect or introduce security defects. The maintainer remains responsible for reviewing, testing, and maintaining the code.

## License

The original Wrapper source code is released under [The Unlicense](LICENSE). The bundled Android system files retain their own licenses and notices, documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Apple proprietary libraries are not included in the source repository but are embedded in private Docker builds. This project is not affiliated with or endorsed by Apple.
