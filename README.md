# apkre — APK Reverse Engineering Platform

Automated API discovery from Android apps. Extracts endpoints, auth tokens, request/response schemas, and generates OpenAPI 3.0 specs — all from a running app on a rooted device.

## What It Does

```
APK → Static Analysis → Dynamic Capture → OpenAPI 3.0 Spec
                ↓               ↓
          URL patterns    Live HTTP traffic
          Auth strings    JWT tokens
          Dart/Flutter    Request/response bodies
```

**apkre** combines static analysis (jadx decompilation, string scanning, Dart binary extraction) with dynamic capture (Frida SSL hooks, logcat parsing, mitmproxy) to produce a complete API specification from any Android app.

## Quick Start

```bash
# Install (core — logcat capture works with just this)
pip install apkre

# Install with all optional dependencies
pip install "apkre[all]"

# Analyze an installed app (auto-pulls APK from device)
apkre analyze --package com.example.app --device <serial>

# Interactive mode — capture while you use the app
apkre analyze --package com.example.app -i

# Static analysis only (no device needed)
apkre analyze --apk app.apk --static-only
```

## Features

### Static Analysis

- **APK unpacking** — handles split APKs (App Bundles) from Play Store
- **jadx/apktool decompilation** — extracts Java source for URL scanning
- **Dart/Flutter binary scanning** — extracts strings from `libapp.so` AOT snapshots
- **Noise filtering** — filters out SDK URLs, XML namespaces, documentation links, telemetry endpoints

### Dynamic Capture

- **Logcat tap** — zero-setup capture for Flutter/Dio apps via `adb logcat`
- **Frida SSL hooks** — intercepts SSL_write/SSL_read for universal HTTPS capture
- **BoringSSL pattern scanning** — finds stripped BoringSSL symbols in Flutter's libflutter.so
- **OkHttp Java hooks** — captures Java-based HTTP clients via Frida
- **mitmproxy integration** — transparent proxy for non-pinned traffic
- **Interactive mode** — real-time endpoint discovery while you use the app

### Token Extraction

- **Heap dump scanning** — extracts JWT tokens from app memory
- **SharedPreferences** — reads auth tokens from XML preference files
- **Frida prefs dump** — enumerates SharedPreferences via Java bridge

### Output Formats

- **OpenAPI 3.0** — complete YAML spec with paths, methods, schemas, auth
- **Postman Collection** — importable collection with variables and auth
- **curl commands** — executable shell script with all discovered endpoints

## Requirements

### Required

- Python 3.11+
- `adb` (Android SDK platform-tools)

### Recommended

- `jadx` — for DEX decompilation (`brew install jadx`)
- `frida` + `frida-server` on device — for SSL interception (`pip install "apkre[frida]"`)
- Rooted Android device or emulator

### Optional

- `mitmproxy` — for Java/OkHttp traffic capture (`pip install "apkre[mitmproxy]"`)
- `genson` — for JSON schema inference (`pip install "apkre[schema]"`)
- `reflutter` — for deeper Dart snapshot analysis
- `strings` (binutils) — for binary string extraction

## Usage

### Full Analysis (Static + Dynamic)

```bash
apkre analyze \
  --package com.bambu.handy \
  --device 00cd45debbb13445 \
  --output api-spec.yaml \
  --postman collection.json \
  --curls curls.sh
```

### Interactive Capture

Interact with the app while apkre records all HTTP traffic in real-time:

```bash
apkre analyze --package com.example.app --interactive
# Use the app on your phone...
# Press Ctrl+C when done
```

### Device Setup

Fix common issues (clock sync, routing tables) before capture:

```bash
apkre device-setup --device <serial>
```

### Prerequisite Check

Verify your environment is ready:

```bash
apkre prereqs --device <serial> --fix
```

## Architecture

```
apkre/
├── static/
│   ├── apk_unpack.py        # APK extraction + split APK handling
│   ├── string_scanner.py    # URL/auth pattern extraction with noise filtering
│   └── dart_scanner.py      # Flutter/Dart AOT binary scanning
├── dynamic/
│   ├── frida_agent.js       # Frida 17.x SSL hooks (system + BoringSSL)
│   ├── frida_controller.py  # Spawn/attach, inject, collect
│   ├── logcat_tap.py        # Flutter Dio log parser with interactive mode
│   ├── mitmproxy_tap.py     # mitmproxy flow capture
│   └── token_extractor.py   # Heap dump + SharedPrefs + Frida prefs
├── analysis/
│   ├── schema_inferrer.py   # JSON → JSONSchema (genson or manual)
│   ├── endpoint_merger.py   # Deduplicate, parameterize, merge bodies
│   └── auth_detector.py     # Auth scheme recognition
├── output/
│   ├── openapi_builder.py   # → OpenAPI 3.0 YAML
│   ├── postman_builder.py   # → Postman Collection v2.1
│   └── curl_builder.py      # → Executable curl script
├── device/
│   ├── setup.py             # Clock sync, routing fix, proxy, CA install
│   └── prereq_check.py      # Environment validation
└── session.py               # SQLite session persistence
```

## Flutter SSL Interception

Flutter apps use BoringSSL statically linked in `libflutter.so` with stripped symbols. apkre uses a three-tier strategy:

### Tier 1: Exported Symbols (debug builds)

Standard `SSL_write`/`SSL_read` export lookup — works on debug and some custom builds.

### Tier 2: ARM64 ADRP+ADD Cross-Reference Resolution (stripped release builds)

BoringSSL embeds error-reporting strings (`"SSL_write\0"`, `"SSL_read\0"`) even in stripped builds. apkre's Frida agent:

1. Finds these strings via `Memory.scanSync`
2. Scans `.text` for ARM64 ADRP instructions targeting the string's page
3. Validates the following ADD instruction matches the page offset
4. Walks backwards from the xref to find the function prologue (`STP X29, X30, [SP, #-N]!`)
5. Hooks at the resolved function address

### Tier 3: Prologue Pattern Scan (fallback)

Searches for functions with `STP X29, X30` + `CBZ X0` (SSL null-check) pattern that also reference the target string within their body.

### Tier 4: reFlutter APK Patching (nuclear option)

If all runtime approaches fail:

```bash
apkre patch --apk app.apk --proxy 10.0.0.1
# Rewrites libflutter.so to disable cert verification
# Redirects all Dart HTTP traffic through your proxy
adb install app_patched.apk
mitmdump -p 8080 --ssl-insecure
apkre analyze --package com.example.app --interactive
```

## Frida Modes

| Mode       | Flag            | Use When                                    |
| ---------- | --------------- | ------------------------------------------- |
| **Spawn**  | (default)       | Fresh capture, need full app lifecycle      |
| **Attach** | `--interactive` | App already running, preserve routing/state |

Attach mode hooks the running process without restarting it — critical for LineageOS/AOSP where Frida spawn breaks WiFi routing tables.

## Known Limitations

- **Dart HTTP bypasses system proxy** — Dart's HTTP client ignores Android's global proxy setting. Use logcat capture, Frida SSL hooks, or `apkre patch` with mitmproxy.
- **Split APKs** — requires a connected device to pull arch-specific splits containing native libraries.
- **ARM64 only** — BoringSSL pattern scanning currently targets ARM64 (aarch64). x86/x86_64 emulators need different instruction patterns.

## Device Notes

### LineageOS / Custom ROMs

- ADB root (`uid=0`) is default — no `su` binary needed
- WiFi routing tables break when Frida spawns apps. Use `--interactive` mode (uses attach) or run `apkre device-setup` to fix routing.
- Clock sync is critical — SSL cert validation fails if device clock drifts

### Emulators

- Works with standard Android emulators (AVD) with root access
- `frida-server` must match your architecture (x86_64 for emulator, arm64 for physical device)
- BoringSSL pattern scanning works best on ARM64 devices; emulators may need `apkre patch` instead

## License

MIT
