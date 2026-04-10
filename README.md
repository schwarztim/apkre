# apkre

**APK Reverse Engineering Platform** — automated API discovery from Android applications.

apkre extracts undocumented API endpoints, authentication tokens, and request/response schemas from Android APKs, then generates production-ready OpenAPI 3.0 specifications. It combines static decompilation with live traffic capture to handle both simple REST apps and hardened Flutter applications with stripped SSL symbols.

---

## The Problem

Android apps communicate with backend APIs that are rarely documented. Security assessments, partner integrations, and competitive analysis all require understanding what endpoints exist, what authentication schemes are in use, and what data structures are exchanged — none of which is available from public documentation.

Manual approaches are slow and incomplete: decompiling an APK captures only hardcoded URLs, while proxying traffic misses endpoints only reachable through specific app flows. Hardened apps add certificate pinning, Dart's proxy-bypassing HTTP client, and stripped native SSL symbols that defeat standard interception.

apkre automates the full pipeline: static analysis to establish a baseline, dynamic capture to observe real traffic, and schema inference to generate a spec that reflects the API as it actually behaves.

---

## Features

### Static Analysis

- APK unpacking with split APK / App Bundle support (pulls architecture-specific splits from device)
- jadx decompilation of DEX bytecode to Java source for URL and auth pattern scanning
- Dart/Flutter AOT binary scanning — extracts API strings from `libapp.so` snapshots without execution
- Noise filtering removes SDK endpoints, XML namespaces, telemetry URLs, and documentation links

### Dynamic Capture

- **Logcat tap** — zero-setup capture for Flutter/Dio apps via `adb logcat`; no device modification required
- **Frida SSL hooks** — intercepts `SSL_write`/`SSL_read` for universal HTTPS capture at the TLS layer
- **BoringSSL symbol resolution** — locates stripped BoringSSL functions in Flutter's `libflutter.so` using ARM64 ADRP+ADD cross-reference analysis when symbols are absent
- **OkHttp hooks** — captures Java-based HTTP clients via Frida Java bridge
- **mitmproxy integration** — transparent proxy capture for non-pinned traffic
- **Interactive mode** — real-time endpoint collection while manually exercising the app

### Token and Credential Extraction

- Heap dump scanning for JWT tokens in app memory
- SharedPreferences extraction from XML preference files
- Frida-driven SharedPreferences enumeration via Java reflection

### Output

- **OpenAPI 3.0 YAML** — complete specification with paths, HTTP methods, inferred schemas, and auth configuration
- **Postman Collection v2.1** — importable collection with environment variables and auth headers
- **curl script** — executable shell script covering all discovered endpoints

---

## Architecture

```
APK / Running App
        |
        +---> Static Analysis                Dynamic Capture
        |     ├── apk_unpack.py              ├── frida_controller.py
        |     ├── string_scanner.py          │   └── frida_agent.js
        |     └── dart_scanner.py            ├── logcat_tap.py
        |                                    ├── mitmproxy_tap.py
        |                                    └── token_extractor.py
        |
        +---> Analysis Layer
        |     ├── endpoint_merger.py   (deduplicate, parameterize paths)
        |     ├── schema_inferrer.py   (JSON body → JSONSchema)
        |     └── auth_detector.py     (Bearer, Basic, API key, custom)
        |
        +---> Output
              ├── openapi_builder.py   → OpenAPI 3.0 YAML
              ├── postman_builder.py   → Postman Collection v2.1
              └── curl_builder.py      → curl script
```

Session state persists to SQLite between runs, so partial captures can be resumed and merged.

---

## Flutter SSL Interception

Flutter apps statically link BoringSSL inside `libflutter.so` with stripped export symbols, defeating standard Frida hooks. apkre uses a four-tier resolution strategy:

**Tier 1 — Exported symbols.** Direct `SSL_write`/`SSL_read` export lookup. Works on debug builds and some custom-compiled apps.

**Tier 2 — ARM64 ADRP+ADD cross-reference resolution.** BoringSSL retains error-string literals (`"SSL_write\0"`, `"SSL_read\0"`) even in stripped release builds. The Frida agent locates these strings via `Memory.scanSync`, scans `.text` for ADRP instructions targeting the string's memory page, validates the following ADD for the correct page offset, then walks backwards to find the function prologue (`STP X29, X30, [SP, #-N]!`). The resolved address is hooked directly.

**Tier 3 — Prologue pattern scan.** Searches for functions matching the `STP X29, X30` + `CBZ X0` pattern (SSL null-check idiom) that also reference the target error string within their body.

**Tier 4 — reFlutter APK patching.** When all runtime approaches fail, `apkre patch` rewrites `libflutter.so` to disable certificate verification and redirect Dart HTTP traffic through a local mitmproxy listener. The patched APK is reinstalled and analyzed in interactive mode.

---

## Requirements

**Required**

- Python 3.11+
- `adb` (Android SDK platform-tools)

**Recommended**

- `jadx` — DEX decompilation (`brew install jadx`)
- Rooted Android device or rooted emulator
- `frida-server` installed on the device matching the installed `frida` Python package version

**Optional**

- `mitmproxy` — transparent proxy capture for Java/OkHttp traffic
- `genson` — JSON schema inference from captured request/response bodies
- `reflutter` — extended Dart snapshot analysis
- `strings` (binutils) — binary string extraction fallback

---

## Installation

```bash
# Core install (logcat capture, static analysis, OpenAPI output)
pip install apkre

# With Frida support
pip install "apkre[frida]"

# With mitmproxy support
pip install "apkre[mitmproxy]"

# Full install (all optional dependencies)
pip install "apkre[all]"
```

---

## Getting Started

### 1. Verify your environment

```bash
apkre prereqs --device <serial> --fix
```

Checks for adb connectivity, root access, frida-server version match, clock sync, and jadx availability. The `--fix` flag attempts to resolve common issues automatically.

### 2. Run a full analysis

```bash
apkre analyze \
  --package com.example.app \
  --device <serial> \
  --output api-spec.yaml \
  --postman collection.json \
  --curls curls.sh
```

apkre pulls the APK from the device, runs static analysis, attaches Frida for SSL interception, and launches the app. Endpoints are collected until you press Ctrl+C or the app exits.

### 3. Interactive capture

For apps where interesting traffic is triggered by specific user flows:

```bash
apkre analyze --package com.example.app --device <serial> --interactive
# Use the app normally on the device
# Press Ctrl+C when done
```

Attach mode hooks a running process without restarting it — required on LineageOS/AOSP where Frida spawn disrupts WiFi routing tables.

### 4. Static analysis only (no device required)

```bash
apkre analyze --apk app.apk --static-only --output api-spec.yaml
```

### 5. Fix device routing issues before capture

```bash
apkre device-setup --device <serial>
```

Syncs the device clock, repairs WiFi routing tables, and configures the proxy if needed.

---

## Frida Modes

| Mode | Flag | Use When |
|------|------|----------|
| Spawn | (default) | Full app lifecycle capture from cold start |
| Attach | `--interactive` | App already running; avoids process restart side effects |

---

## Known Limitations

**Dart HTTP ignores the Android system proxy.** Dart's HTTP client routes directly without consulting Android's global proxy setting. Use logcat capture, Frida SSL hooks, or `apkre patch` with mitmproxy instead.

**Split APKs require a connected device.** Architecture-specific native libraries live in split APKs that must be pulled from a device; they are not available in the base APK alone.

**BoringSSL pattern scanning targets ARM64.** The ADRP+ADD cross-reference strategy is specific to ARM64 (aarch64). x86/x86_64 emulators require different instruction patterns or the reFlutter patch path.

---

## Device Notes

**LineageOS / Custom ROMs**

ADB root (`uid=0`) is available by default — no `su` binary required. Frida spawn mode disrupts WiFi routing tables on LineageOS; use `--interactive` (attach mode) or run `apkre device-setup` beforehand.

**Emulators**

Standard Android AVDs with root access are supported. The `frida-server` binary must match the emulator architecture (x86_64 for AVD, arm64 for physical devices). BoringSSL pattern scanning is most reliable on ARM64 physical devices; emulators may require the `apkre patch` approach.

---

## License

MIT
