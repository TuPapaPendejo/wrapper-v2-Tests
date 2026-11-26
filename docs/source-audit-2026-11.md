# Source audit and reverse-engineering notes — November 2026

## Review identity and limits

- Repository: `TuPapaPendejo/wrapper-v2-Tests`
- Reviewed baseline: `main` at `9a6f29f493b1bac5325105ab6edf5dbd8caaae8c`
- Remediation baseline: `fix/device-info-apple-auth-1109` at `6918066e51926427c133230ececae6154d4d70dd`
- Follow-up branch: `audit/security-hardening` (draft PR; not merged into the authentication branch or `main`)
- Scope: Rust HTTP API and supervisor; native C++ worker, session and playback
  paths; x86-64 and ARM64 context-capture hooks; launcher and namespaces;
  runtime profiles and binary pins; APK/APKM staging; Docker/Compose; tests,
  CI and operational documentation.
- Method: source and configuration review through the GitHub repository
  contents API, comparison against the upstream Wrapper Lite device-identity
  implementation, and review of the supplied reproduction in
  [glomatico/wrapper-v2 issue 23](https://github.com/glomatico/wrapper-v2/issues/23).
- This document records the **source-level review**; that review did not itself
  execute Apple's proprietary code. A separate clean x86_64 Docker deployment,
  login, 2FA, session recovery, playback, and key-route reproduction was later
  supplied and is documented near the end. CI's synthetic worker still cannot
  validate Apple's proprietary `AuthenticateFlow`.

## Executive findings

1. **Confirmed fresh-install authentication compatibility defect — fixed in this
   change.** The auto-generated device identity used an obsolete client tuple
   (`Music/4.9`, Samsung S9, build 7663313) and generated a 128-bit suffix
   (32 hex characters). Issue 23 comment
   [7162866962](https://github.com/glomatico/wrapper-v2/issues/23#issuecomment-7162866962)
   reports a controlled successful login after changing only
   `WRAPPER_DEVICE_INFO` to the `Music/5.0.2` / Pixel 8 / build 7663314 tuple
   with an eight-byte random Android ID. The author did not isolate the two
   fields experimentally. The new default adopts the complete tested tuple
   and ID representation, and adds tests for that exact shape.
2. **Persisted sessions are deliberately not migrated.** The Rust identity file
   and native `.worker-device` hash form a pair. Silently regenerating either
   value can make an existing Apple Music cache unusable. The patch changes
   only identities generated for new installations and explicitly tests that
   an existing 1.0.0 identity is left byte-for-byte unchanged.
3. **The API has no TLS and its Bearer authentication is opt-in.** The
   follow-up adds `WRAPPER_API_TOKEN`; when configured, all routes except
   `GET /health` require a Bearer token. When unset, legacy 1.0.0 behavior is
   intentionally preserved, so the API remains unauthenticated at application
   level. `GET /session/credentials` exports session tokens. Keep the default
   loopback binding or use an authenticated TLS gateway for remote access.
4. **The native implementation is highly version- and ABI-specific by design.**
   Symbols, object layouts, linker behavior, capture hook addresses, register
   states, byte offsets and expected context sizes are coupled to exact
   Apple/Android binaries. SHA-256 pins and runtime handshakes fail closed, but
   they do not replace real integration testing against the pinned APKM.
5. **The HTTP and lifecycle tests are synthetic.** They give useful coverage of
   routing, IPC, retry behavior, 2FA orchestration, redaction, staging and
   namespace teardown. They do not execute Apple's native authentication or
   prove that a real Apple account can log in.

## Detailed findings

### F-01 — Fresh-install device identity did not match the working client profile

**Severity:** High for first-login availability  
**Status:** Fixed and exercised in the supplied clean x86_64 reproduction. ARM64 and broader native/media behavior remain unverified.

Baseline implementation in `src/device_info.rs` used:

- `Music/4.9/Android/10/Samsung S9/7663313/en-US/en-US`
- 16 random bytes, formatted as a 32-character hexadecimal suffix.

The issue 23 reproduction records the same native failure on a fresh x86-64
build-1109 install and then a successful 2FA login after changing only the
device-info override to:

```text
Music/5.0.2/Android/10/Pixel 8/7663314/en-US/en-US/<16 lowercase hex chars>
```

The upstream [WorldObservationLog Wrapper Lite source](https://github.com/WorldObservationLog/wrapper/blob/lite/lite/lite_main.cpp)
also documents the nine-field device tuple and computes Android ID as a
64-bit FNV-1a value formatted to 16 hexadecimal characters. The issue's
successful test uses a random 64-bit value instead; this project continues
to use cryptographically random bytes rather than deriving an ID from the
account username.

**Change:** new installations now use that known-working client tuple and
eight random bytes (64 bits). The random ID is persisted atomically with mode
0600. Temporary-file names retain their independent 128-bit randomness.

**Compatibility:** explicit `WRAPPER_DEVICE_INFO` overrides remain supported.
Existing `.wrapper-device-info` files are read as-is, including old 32-hex
suffixes. No old identity, native hash, or saved session is rewritten.

**Unresolved experimental distinction:** the report changed both the client
tuple and the ID length at once. The evidence proves the combined value works
in that reporter's environment; it does not establish which individual field
Apple rejected. A later controlled test can vary one field at a time, but a
new installation should use the already demonstrated working combination.

### F-02 — Runtime API-level documentation disagreed with the build profiles

**Severity:** Low  
**Status:** Fixed in this change.

The README described the ARM64 Android system image as API 22. Both pinned
profiles declare API 21, and the Docker/CMake build configures and enforces
Android platform 21. The requirement table now reports API 21 for both ABIs.

### F-03 — Unauthenticated HTTP API and credential export

**Severity:** High if reachable by an untrusted client  
**Status:** Partially remediated with an opt-in Bearer control; TLS remains external.

`WRAPPER_API_TOKEN` is now parsed as a bounded, restricted-character secret.
When configured, every route except `GET /health` requires
`Authorization: Bearer <token>`; missing or invalid values receive HTTP 401.
The token is held in `Zeroizing<String>`, is not logged, and is never passed to
the native worker. Tests cover legacy mode, valid and invalid headers, and the
public health route.

**Compatibility choice:** when `WRAPPER_API_TOKEN` is absent, the existing
1.0.0 no-auth API behavior remains unchanged. This is necessary to avoid
silently breaking current clients. The optional token therefore does not make
a default deployment authenticated. `GET /session/credentials` still exports
developer and media-user tokens, and Docker administrators can inspect
container environment variables. Keep the loopback binding, protect
`.env`/Docker access, and use an authenticated TLS gateway for deliberate
remote access. Do not assume a client such as Gamdl can send this custom header
unless its configured provider has been tested.

**Operational control:** keep the host binding on loopback, do not publish the
container port to an untrusted network, restrict Docker/network access, and
put any remote access behind an independently authenticated TLS gateway.
Do not treat a private container network as a substitute for application
authentication when other tenants or workloads can join it.

### F-04 — Human 2FA wait has no server-side deadline

**Severity:** Medium when an untrusted client can reach the API  
**Status:** Partially remediated with an opt-in idle timeout; indefinite wait remains the default.

`WRAPPER_2FA_TIMEOUT_SECONDS` accepts 1–86400 seconds. An absent value or
`0` preserves the previous indefinite wait to avoid breaking slow or
legitimate human approval. When set, expiry clears the pending challenge,
emits `session.challenge_expired` with only the configured duration, discards
the native worker, and releases the single-worker lock. The synthetic
auto-auth test covers expiry, pending-challenge removal, logged-out state, and
the ability to start a subsequent login. A live Apple 2FA timeout was not
tested.

### F-05 — Native ABI and capture hooks are pinned to exact binary layouts

**Severity:** High impact if pins or offsets drift  
**Status:** Guarded by hashes and fail-closed checks; requires ongoing review.

The native worker uses mangled Apple C++ symbols, hand-declared ABI return
types, shared-pointer control-block adoption, hard-coded object storage sizes,
and a fixed offset to read a response payload. The capture implementations
also use architecture-specific instruction addresses, byte prefixes, register
predicates, stack ranges, pointer remapping and hundreds of fixed state offsets.
The runtime verifies Apple shared-library SHA-256 values and hook instruction
prefixes before use; profile metadata and HTTP response contracts validate
captured context sizes.

These guards are valuable: do not relax them to make a different APK appear
compatible. The follow-up CI now builds and runs the host-side C++ protocol and
launcher unit tests in addition to Rust and Python tests. This does not compile
or execute the proprietary Apple Android worker in the CI runner. Any Apple
Music version, library, NDK, Dobby, linker or ABI change remains a separate
reverse-engineering target requiring validation on both architectures. A
successful compile alone does not prove that native object sizes or capture
state are correct.

### F-06 — CI does not exercise the proprietary Apple authentication path

**Severity:** Medium  
**Status:** Test-environment limitation.

The follow-up workflow pins checkout/setup-python actions to immutable
commit SHAs and uses Rust 1.100.0 for formatting, Clippy, and unit tests. It
adds CMake/CTest execution of `common_tests` and `worker-launch`, retains the
Linux namespace lifecycle test, and runs the synthetic HTTP, supervisor,
staging, and environment-control tests. The staging fixtures remain synthetic.

The workflow does not receive the proprietary Apple package or Apple
credentials and does not execute the native Apple libraries. Green CI can
validate shared Rust, HTTP, protocol, launcher, and staging contracts; it
cannot confirm `AuthenticateFlow`, live 2FA, cached-token validation,
playback, or actual Temari context capture. Private real-runtime tests remain
necessary for those paths.

### F-07 — Builder inputs are not fully reproducible

**Severity:** Medium for supply-chain/rebuild reproducibility  
**Status:** Partially remediated; Docker base and APT remain mutable.

The follow-up pins the Rust toolchain to 1.100.0 in
`rust-toolchain.toml` and the Docker build. GitHub Actions now pins the
checkout, Rust-toolchain action, and setup-python action to immutable commit
SHAs. The Android NDK archive is checksum-verified and external native source
dependencies are pinned to Git commits.

The Docker base remains the mutable `debian:13.2` tag, and APT still resolves
packages from the configured Debian repositories at build time. These can
change between builds. The follow-up deliberately does not claim hermetic
reproducibility or replace the base image without a verified digest and a
successful multi-architecture Docker build. Pinning the base manifest by
digest and using a dated Debian snapshot remain outstanding work.

### F-08 — Authentication validation uses a separately hard-coded request header

**Severity:** Low / investigation item  
**Status:** Not changed; no evidence it caused the reported failure.

`native/session.cpp` constructs a POST header identifying
`Music/4.9 Android/10 model/Samsung S9 build/7663313`, while the tested
working `WRAPPER_DEVICE_INFO` tuple is Music 5.0.2 / Pixel 8 / 7663314.
This header is used by the later signed session-validation request, not to
construct the nine-field `RequestContext` identity itself. The issue reporter's
working override shows that this mismatch did not prevent the reported login
from completing. It should nevertheless be tested during private session
restore and token validation before changing it; blindly deriving or changing
the header could introduce a second variable.

### F-09 — Certificate trust is build-host dependent

**Severity:** Medium when the worker must reach an Apple endpoint whose root is
absent from the builder's CA bundle  
**Status:** Deliberately unchanged; requires private session-validation evidence.

`tools/prepare_rootfs.py` still stages the CA bundle supplied by the build
environment. The follow-up records its SHA-256 in the generated
`worker-profile.json`, allowing the exact bundle used for a staged rootfs to
be identified without copying certificate contents into metadata. A test
checks the digest and confirms that the certificate bytes are not serialized.

This does **not** add or verify the Apple Root CA, establish that a particular
root is trusted by Apple, or prove that `gsa.apple.com`/native
`AuthenticateFlow` succeeds. The issue 23 report separately found a missing
Apple Root CA in one staged bundle; appending it made `curl` verification
succeed but did not fix the authentication failure. Any future trust-anchor
change requires an authoritative Apple source, published fingerprint
verification, and private endpoint/session tests.

### F-10 — Sensitive data is intentionally omitted from logs, but runtime access
still matters

**Severity:** Medium  
**Status:** Log redaction retained and extended in documentation; deployment access remains sensitive.

HTTP access logs still omit raw paths, query strings, headers, credentials,
challenge values, key URIs, tokens, and contexts. The optional Bearer token is
never logged, and the timeout event records only a duration. The token itself
is supplied through container environment configuration; Docker administrators
and users with inspect access can read it. Docker logs, the data volume,
`.env`, the Docker socket and the final image remain security-sensitive.
Keep them private and restrict daemon access.

## Architecture map

1. **Build/staging:** `tools/build-docker.sh` supplies the operator's APK/APKM
   to a named BuildKit context. `tools/prepare_rootfs.py` verifies the selected
   profile's manifests and Apple library hashes, verifies vendored Android
   system files, records the staged CA-bundle SHA-256 in rootfs metadata, and
   stages the runtime.
2. **Rust HTTP facade:** `src/main.rs`, `src/http.rs`, `src/config.rs`,
   `src/profile.rs` parse configuration, optional Bearer authentication and
   timeout settings, and expose the unversioned API.
3. **Supervisor:** `src/worker.rs` serializes operations, frames IPC,
   enforces timeouts and response limits, handles worker recycling, and
   coordinates 2FA.
4. **Namespace launcher:** `native/launcher.cpp` creates mount/PID namespaces,
   chroots into the staged Android rootfs, starts the Android worker, reaps
   children and tears down the namespace when IPC closes.
5. **Native worker:** `native/main.cpp`, `runtime.cpp`, `session.cpp`,
   `playback.cpp` and `context.cpp` call the pinned Apple libraries.
6. **Context capture:** `capture_x86_64.cpp` and `capture_arm64.cpp` use
   different, profile-specific hooks and memory layouts. The Rust profile
   contract checks the serialized context before it is returned to a client.

## Verification matrix

| Area | Source/test coverage in this branch | Live validation still required |
| --- | --- | --- |
| Device identity | persistence, atomic creation, concurrency, overrides and no-migration tests | clean x86_64 fresh login/2FA succeeded; ARM64 live test outstanding |
| HTTP API | legacy mode and optional Bearer-token tests, 401 handling, public health route, validation, and redaction | x86_64 login/session flow succeeded before this follow-up; Bearer mode is synthetic-only |
| Supervisor / 2FA | synthetic worker recycle/recovery, cancellation, configured timeout expiry, pending-state cleanup and re-login | live Apple 2FA timeout and long-wait behavior remain untested |
| Native protocol | framing, size/depth checks, continuation validation, SHA-256/base64; CMake/CTest added for common C++ tests | proprietary native Apple worker and both ABI capture flows remain unverified by CI |
| Launcher | disposable PID/mount namespaces, orphan reaping, teardown and C++ launcher target | other kernels and container security profiles remain environment-dependent |
| APK/APKM staging | synthetic package fixtures, manifest/hash/ELF and duplicate-library rejection; CA bundle digest metadata | exact package extraction is private; ARM64 Docker build not verified here |
| Build provenance | Rust version and GitHub Actions pinned; NDK and source dependencies pinned | Debian base digest and APT snapshot still mutable |
| Session-validation header | static source review only; deliberately unchanged | private restore/token-validation test needed before altering the client header |
| x86_64/ARM64 capture | static profiles, offsets, hashes and context length contracts | x86_64 playback and `/key` returned HTTP 200; context bytes not independently validated; ARM64 not tested |

## Remediation status for the audit/security-hardening draft

This follow-up is intentionally based on the authentication-fix branch and is
kept in a separate draft pull request. It does not alter the authentication
branch, `main`, the proprietary native ABI/capture layouts, or the signed
session-validation request header.

| Finding | Change in this draft | Remaining qualification |
| --- | --- | --- |
| F-03 | Optional Bearer-token middleware; `/health` remains public; 401 tests | Disabled by default for client compatibility; no TLS; Docker administrators can inspect environment variables |
| F-04 | Optional 1–86400 second 2FA idle timeout; worker discarded on expiry | Unset/zero remains indefinite; only synthetic 2FA tested |
| F-05 | Added CMake/CTest coverage for shared C++ protocol and launcher | Apple-specific native worker/ABI/capture still need private runtime tests |
| F-06 | Pinned Rust and Actions; expanded CI to run native C++ tests | CI still uses synthetic workers and no proprietary Apple package or credentials |
| F-07 | Rust toolchain pinned to 1.100.0; GitHub Actions pinned by SHA | Debian base tag and APT repository/package state remain mutable |
| F-08 | No native header change; retained as an explicit investigation item | Must compare fresh login and cached-session restore privately before changing |
| F-09 | Record CA bundle SHA-256 in generated rootfs metadata | No Apple root injected; bundle contents and Apple endpoint trust not validated |
| F-10 | Document token/secret handling and maintain log redaction | Environment, Docker inspect, session volume, logs, daemon and image remain sensitive |

The synthetic tests and documentation are part of this draft and have **not**
yet passed a GitHub Actions run at the time this document was written. A green
CI run will still not establish live Apple authentication, cached-session
restore, playback correctness, context-byte correctness, or ARM64 behavior.

## Private build-input and verification boundary

The selected profiles target Apple Music package `com.apple.android.music`,
version `3.6.0-beta`, build `1109`, with architecture-specific manifest and
native-library hashes. The operator supplies an authorized local standalone
APK or supported split APKM; the repository does not distribute that package
or identify a third-party download source.

`tools/prepare_rootfs.py` verifies the required base/split manifest digest,
selects the expected architecture split, checks the ELF machine type, and
compares every extracted Apple native library against the selected profile's
SHA-256 value. It stages only the allowlisted native libraries and the
separately pinned Android system files.

The build helper also computes the SHA-256 of the complete local APK/APKM and
passes it to BuildKit. The Dockerfile recomputes that same value inside the
builder. This verifies that the supplied build input remains unchanged across
the BuildKit hand-off and participates in cache invalidation. It is **not** a
publisher-authenticity check and is not a comparison against a trusted,
hard-coded whole-archive checksum. Obsolete profile metadata that implied
archive-level validation was removed because the staging code does not
perform that check.

Do not commit the input package, extracted proprietary libraries, account
credentials, tokens, or session data. The resulting local image contains
extracted Apple libraries and must remain private.

## Successful clean-install reproduction — 25 November 2026 local time

A subsequent clean installation confirmed the identity correction on x86_64.
The log timestamps below were emitted in UTC on 26 November 2026; the test took
place on 25 November local time (UTC-06:00).

### Environment

- Windows host: Windows 10 IoT Enterprise LTSC 2021.
- Linux runtime: openSUSE Tumbleweed under an updated WSL installation.
- Wrapper deployment: Docker Compose in the Linux environment.
- Wrapper version: 1.0.0.
- Native worker: x86_64.
- Apple Music: pinned 3.6.0-beta, build 1109.
- Gamdl: freshly installed separately on Windows.
- Test scope: x86_64 only.

### Authentication evidence

The sanitized log shows:

- The Rust API started successfully.
- The x86_64 worker initialized successfully.
- A previous-session restore returned `session_expired` (HTTP 403), which
  preceded a new interactive login and did not prevent it.
- `POST /session/login` returned HTTP 202, the expected pending-2FA response.
- The challenge completed with HTTP 200 and Wrapper emitted
  `session.authenticated`.
- `GET /session` and `GET /session/credentials` returned HTTP 200.

### Session-recovery and playback evidence

Later, after the native worker was stopped and replaced:

- The replacement x86_64 worker started.
- Wrapper emitted `session.recovered`.
- `GET /session/credentials` returned HTTP 200.
- Two playback requests returned HTTP 200.
- Two `/key` requests returned HTTP 200.

This validates the fresh-login/2FA path and the exercised x86_64 session-recovery,
playback, and key/context HTTP paths in the reported environment. It does not
validate every catalog item, every media codec, all playback edge cases, or
the internal correctness of context bytes beyond the successful endpoint
responses in this test.

### ARM64 qualification

The identity generation and validation reside in shared Rust code, not in
architecture-specific native capture files. Thus, the device-info change is
expected to apply identically on ARM64. However, this reproduction did not
build or run an ARM64 image and did not test ARM64 authentication, playback,
or context capture. ARM64 must remain marked unverified until those steps are
performed on an ARM64-capable or emulated Buildx/runtime environment.

### Sanitized log evidence (relevant events)

```jsonl
{"timestamp":"2026-11-26T01:52:54.580290Z","level":"INFO","event":"server.started","version":"1.0.0","protocol":1,"architecture":"x86_64","host":"0.0.0.0","port":80}
{"timestamp":"2026-11-26T01:53:31.644440Z","level":"INFO","event":"http.request","request_id":2,"method":"GET","path":"/session","status":200,"duration_ms":1013}
{"timestamp":"2026-11-26T01:58:32.479258Z","level":"WARN","event":"worker.error","operation":"session.restore","code":"session_expired","restart_required":false}
{"timestamp":"2026-11-26T01:58:32.479323Z","level":"WARN","event":"http.request","request_id":6,"method":"POST","path":"/session/restore","status":403,"duration_ms":1,"code":"session_expired"}
{"timestamp":"2026-11-26T01:58:33.853034Z","level":"INFO","event":"http.request","request_id":8,"method":"GET","path":"/session","status":200,"duration_ms":0}
{"timestamp":"2026-11-26T01:58:46.069488Z","level":"INFO","event":"http.request","request_id":9,"method":"POST","path":"/session/login","status":202,"duration_ms":6311}
{"timestamp":"2026-11-26T01:59:10.838309Z","level":"INFO","event":"session.authenticated"}
{"timestamp":"2026-11-26T01:59:10.838357Z","level":"INFO","event":"http.request","request_id":10,"method":"POST","path":"/session/challenge","status":200,"duration_ms":4444}
{"timestamp":"2026-11-26T01:59:10.846869Z","level":"INFO","event":"http.request","request_id":11,"method":"GET","path":"/session","status":200,"duration_ms":0}
{"timestamp":"2026-11-26T01:59:10.853881Z","level":"INFO","event":"http.request","request_id":12,"method":"GET","path":"/session/credentials","status":200,"duration_ms":0}
{"timestamp":"2026-11-26T02:14:39.596825Z","level":"INFO","event":"worker.started","architecture":"x86_64"}
{"timestamp":"2026-11-26T02:14:43.461339Z","level":"INFO","event":"session.recovered"}
{"timestamp":"2026-11-26T02:14:43.461481Z","level":"INFO","event":"http.request","request_id":17,"method":"GET","path":"/session","status":200,"duration_ms":4540}
{"timestamp":"2026-11-26T02:14:43.471588Z","level":"INFO","event":"http.request","request_id":18,"method":"GET","path":"/session/credentials","status":200,"duration_ms":0}
{"timestamp":"2026-11-26T02:14:45.062051Z","level":"INFO","event":"http.request","request_id":19,"method":"GET","path":"/playback","status":200,"duration_ms":356}
{"timestamp":"2026-11-26T02:14:45.388081Z","level":"INFO","event":"http.request","request_id":20,"method":"GET","path":"/playback","status":200,"duration_ms":317}
{"timestamp":"2026-11-26T02:14:47.230518Z","level":"INFO","event":"http.request","request_id":21,"method":"GET","path":"/key","status":200,"duration_ms":321}
{"timestamp":"2026-11-26T02:14:47.609184Z","level":"INFO","event":"http.request","request_id":22,"method":"GET","path":"/key","status":200,"duration_ms":309}
```

No username, password, 2FA code, cookie, token value, signed URL, or account
identifier appears in this event excerpt.
