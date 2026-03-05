/**
 * Frida SSL hook agent — Frida 17.x compatible.
 *
 * Three-tier hooking strategy for Flutter/BoringSSL:
 *   1. Try exported symbols (debug builds)
 *   2. ARM64 ADRP+ADD xref resolver (stripped release builds)
 *   3. Function prologue signature scan (universal fallback)
 *
 * Also hooks system libssl.so and Java OkHttp.
 */

"use strict";

// ─── Utility ─────────────────────────────────────────────────────────────────

function bufToStr(buf) {
  if (!buf) return "";
  try {
    var arr = new Uint8Array(buf);
    if (arr.length > 8192) {
      var result = "";
      for (var i = 0; i < arr.length; i += 8192) {
        var chunk = arr.subarray(i, Math.min(i + 8192, arr.length));
        result += String.fromCharCode.apply(null, chunk);
      }
      return result;
    }
    return String.fromCharCode.apply(null, arr);
  } catch (e) {
    return "";
  }
}

// ─── SSL hooks ───────────────────────────────────────────────────────────────

function hookSslFunction(addr, label, direction) {
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave: function (retval) {
        var n = retval.toInt32();
        if (n > 0) {
          try {
            var data = Memory.readByteArray(this.buf, Math.min(n, 65536));
            send({ type: direction, label: label, data: bufToStr(data) });
          } catch (e) {}
        }
      },
    });
    send({ type: "hook_ok", label: label });
    return true;
  } catch (e) {
    send({ type: "hook_error", label: label, error: e.message });
    return false;
  }
}

function hookSslModule(mod, label) {
  var writeOk = false,
    readOk = false;
  var sslWrite = mod.findExportByName("SSL_write");
  var sslRead = mod.findExportByName("SSL_read");

  if (sslWrite)
    writeOk = hookSslFunction(sslWrite, label + ":SSL_write", "ssl_write");
  if (sslRead)
    readOk = hookSslFunction(sslRead, label + ":SSL_read", "ssl_read");
  return writeOk || readOk;
}

// ─── ARM64 ADRP+ADD cross-reference resolver ─────────────────────────────────
//
// BoringSSL embeds function name strings ("SSL_write\0", "SSL_read\0") for
// error reporting. In stripped builds these strings still exist, and the
// functions that use them reference them via ADRP+ADD instruction pairs.
//
// Strategy:
//   1. Find the string address in .rodata
//   2. Scan .text for ADRP instructions whose target page matches the string page
//   3. Check the following instruction is ADD with the correct page offset
//   4. Walk backwards from that ADRP to find the function prologue (STP X29, X30, ...)
//   5. That prologue is the function entry point to hook

function resolveByAdrpXref(mod, strAddr) {
  var base = mod.base;
  var size = mod.size;
  var strPage = strAddr.and(ptr("0xFFFFFFFFFFFFF000"));
  var strOff = strAddr.toUInt32() & 0xfff;

  // Scan the module for ADRP instructions that reference strPage
  // We scan in 4-byte steps (ARM64 instructions are fixed 4 bytes)
  var candidates = [];
  var scanSize = Math.min(size, 64 * 1024 * 1024); // cap at 64MB

  for (var offset = 0; offset < scanSize; offset += 4) {
    var pc = base.add(offset);
    var insn;
    try {
      insn = pc.readU32();
    } catch (e) {
      continue;
    }

    // ADRP: bit[31]=1, bits[28:24]=10000
    // Encoding: [1] [immlo:30-29] [10000] [immhi:23-5] [Rd:4-0]
    if ((insn & 0x9f000000) !== 0x90000000) continue;

    // Decode ADRP immediate
    var immhi = (insn >> 5) & 0x7ffff; // bits 23:5
    var immlo = (insn >> 29) & 0x3; // bits 30:29
    var imm = (immhi << 2) | immlo;
    // Sign-extend 21-bit value
    if (imm & 0x100000) imm = imm - 0x200000;
    // Target page = (PC & ~0xFFF) + (imm << 12)
    var pcPage = pc.and(ptr("0xFFFFFFFFFFFFF000"));
    var targetPage = pcPage.add(ptr(imm * 4096));

    if (!targetPage.equals(strPage)) continue;

    // Check next instruction: ADD Xd, Xn, #strOff
    // ADD immediate: [sf:31] [0] [0] [100010] [sh:22] [imm12:21-10] [Rn:9-5] [Rd:4-0]
    // For 64-bit (sf=1): 0x91000000 base
    var nextPc = pc.add(4);
    var nextInsn;
    try {
      nextInsn = nextPc.readU32();
    } catch (e) {
      continue;
    }

    // Check it's an ADD immediate (64-bit, no shift)
    if ((nextInsn & 0xffc00000) !== 0x91000000) continue;

    var addImm = (nextInsn >> 10) & 0xfff;
    if (addImm !== strOff) continue;

    // Verify the Rd of ADRP matches Rn of ADD
    var adrpRd = insn & 0x1f;
    var addRn = (nextInsn >> 5) & 0x1f;
    if (adrpRd !== addRn) continue;

    // Found an ADRP+ADD pair referencing our string!
    candidates.push(pc);
  }

  if (candidates.length === 0) return null;

  send({
    type: "hook_info",
    label: "adrp-xref",
    msg: "Found " + candidates.length + " xrefs to string at " + strAddr,
  });

  // For each xref, walk backwards to find function prologue
  for (var i = 0; i < candidates.length; i++) {
    var funcAddr = findFunctionPrologue(candidates[i]);
    if (funcAddr) return funcAddr;
  }

  return null;
}

function findFunctionPrologue(instrAddr) {
  // Walk backwards up to 256 instructions looking for STP X29, X30, [SP, #-N]!
  // This is the standard ARM64 function prologue that saves frame pointer + link register
  //
  // STP X29, X30, [SP, #imm]!  (pre-index)
  // Encoding: [10] [101] [0011] [0] [imm7:21-15] [Rt2:14-10=30] [Rn:9-5=31] [Rt:4-0=29]
  // Fixed bits: Rt=29(X29=0x1d), Rt2=30(X30=0x1e), Rn=31(SP=0x1f)
  // So low 15 bits = (30 << 10) | (31 << 5) | 29 = 0x7BFD
  // And bits[31:25] = 1010100 1 = 0xA9 (with the pre-index bit set: 10 101 0011 x)
  // Actually: STP (pre-index 64-bit) = 10 101 00 110 imm7 Rt2 Rn Rt
  // = 0xA9800000 | (imm7 << 15) | (Rt2 << 10) | (Rn << 5) | Rt
  // Mask for fixed fields: 0xFFE003FF → value: 0xA9807BFD (with negative imm)
  // But imm7 varies, so mask: 0xFC0003FF, value: 0xA9007BFD (for any signed offset pre-index)
  // Actually more precisely: opc=10, V=1/0... let me just check the specific pattern.
  //
  // Let's use a broader check: low 10 bits = (SP<<5)|X29 = 0x3FD, Rt2=X30 at bits[14:10]=0x1E
  // Combined: bits[14:0] = (0x1E << 10) | 0x3FD = 0x7BFD
  // bits[31:30] = 10 (64-bit), bits[29:27] = 101, bit[26] = 0 (not SIMD)
  // bits[25:23] = 011 (pre-index writeback)
  // So mask = 0xFFE003FF is too strict due to imm7. Use: 0xFC0003FF
  // and check value = (10 101 001 1 << 22 | 0x7BFD) → need to be more careful.
  //
  // Simpler approach: just check the lower 15 bits and upper 10 bits pattern.

  for (var back = 0; back < 1024; back += 4) {
    var addr = instrAddr.sub(back);
    var insn;
    try {
      insn = addr.readU32();
    } catch (e) {
      continue;
    }

    // STP X29, X30, [SP, #imm7]! (pre-index)
    // Bits: 10 1010 011 x xxxxxxx 11110 11111 11101
    // Mask the variable imm7 field (bits 21:15):
    // Fixed: bits[31:30]=10, bits[29:25]=10100, bit[24]=1, bit[23]=1
    //        bits[14:10]=11110(X30), bits[9:5]=11111(SP), bits[4:0]=11101(X29)
    // = upper byte: 0xA9, bit24=1, bit23=1 → 0xA9C00000 base (but imm7 varies)
    // Mask: 0xFFC07FFF → but that's wrong because imm7 is in 21:15
    // Let me just check: (insn & 0x7E4003FF) === 0x29007BFD for any STP pre/post/signed-offset

    // Check low 15 bits: Rt2=30, Rn=31, Rt=29 → 0x7BFD
    if ((insn & 0x7fff) !== 0x7bfd) continue;

    // Check it's an STP (opc=10 for 64-bit, bit26=0 for non-SIMD, bits 29:27 = 101)
    // bit31:30 = 10, bit29 = 1, bit28:27 = 01 → top 5 bits = 10101 = 0xA8-0xA9 range
    var top = (insn >>> 25) & 0x7f; // bits 31:25
    // STP 64-bit variants: signed offset (0x52), pre-index (0x53), post-index (0x51)
    // In hex of bits[31:22]: 1010100 1 1x (pre-index) or 1010100 1 0x (post/signed)
    if (top !== 0x52 && top !== 0x53 && top !== 0x51) continue;

    // This is STP X29, X30, [SP, ...]! → function prologue
    return addr;
  }
  return null;
}

// ─── Function prologue signature scan (fallback) ─────────────────────────────
//
// If ADRP xref fails, scan for the SSL_write function signature directly.
// BoringSSL's SSL_write checks ssl->method->write_app_data early in the function.
// The pattern is roughly:
//   STP X29, X30, [SP, #-N]!
//   MOV X29, SP
//   STP X19, X20, [SP, #offset]  (or more callee-saved regs)
//   ...
//   CBZ X0, <error>              (null check on SSL* arg)
//   LDR X8, [X0, #offset]        (load ssl->method or ssl->s3)
//
// We search for CBZ X0 near a function prologue, which is distinctive because
// SSL_write is one of the few BoringSSL functions that takes SSL* as first arg
// and immediately null-checks it.

function findByProloguePattern(mod, strAddr, funcName) {
  // This is a heuristic fallback. We look for functions that:
  // 1. Start with STP X29, X30
  // 2. Have CBZ X0 within first 8 instructions (null-check SSL* param)
  // 3. Reference our target string address within ~200 instructions
  //
  // This narrows candidates significantly in a ~40MB binary.

  var base = mod.base;
  var size = mod.size;
  var scanLimit = Math.min(size, 64 * 1024 * 1024);

  // First, find all STP X29, X30 prologues near CBZ X0
  var funcCandidates = [];

  for (var off = 0; off < scanLimit; off += 4) {
    var addr = base.add(off);
    var insn;
    try {
      insn = addr.readU32();
    } catch (e) {
      continue;
    }

    // STP X29, X30 check (same as above)
    if ((insn & 0x7fff) !== 0x7bfd) continue;
    var top = (insn >>> 25) & 0x7f;
    if (top !== 0x52 && top !== 0x53 && top !== 0x51) continue;

    // Check for CBZ X0 within next 8 instructions
    var hasCbzX0 = false;
    for (var j = 1; j <= 8; j++) {
      var ni;
      try {
        ni = addr.add(j * 4).readU32();
      } catch (e) {
        break;
      }
      // CBZ X0: 1011 0100 [imm19] [Rt=00000]
      // = 0xB4000000 | (imm19 << 5) | 0
      // Mask Rt: ni & 0xFF00001F === 0xB4000000
      if ((ni & 0xff00001f) === 0xb4000000) {
        hasCbzX0 = true;
        break;
      }
    }

    if (hasCbzX0) {
      funcCandidates.push(addr);
    }
  }

  send({
    type: "hook_info",
    label: "prologue-scan",
    msg:
      funcName +
      ": found " +
      funcCandidates.length +
      " STP+CBZ X0 candidates (filtering by string ref...)",
  });

  // Now check which candidates reference our string within ~200 instructions
  if (!strAddr) return null;

  var strPage = strAddr.and(ptr("0xFFFFFFFFFFFFF000"));
  var strOff = strAddr.toUInt32() & 0xfff;

  for (var ci = 0; ci < funcCandidates.length; ci++) {
    var funcStart = funcCandidates[ci];
    // Scan next 200 instructions for ADRP+ADD to our string
    for (var k = 0; k < 200; k++) {
      var pc = funcStart.add(k * 4);
      var ins;
      try {
        ins = pc.readU32();
      } catch (e) {
        break;
      }

      if ((ins & 0x9f000000) !== 0x90000000) continue; // not ADRP

      var immhi = (ins >> 5) & 0x7ffff;
      var immlo = (ins >> 29) & 0x3;
      var imm = (immhi << 2) | immlo;
      if (imm & 0x100000) imm = imm - 0x200000;
      var pcP = pc.and(ptr("0xFFFFFFFFFFFFF000"));
      var tgtPage = pcP.add(ptr(imm * 4096));

      if (!tgtPage.equals(strPage)) continue;

      // Check ADD with correct offset
      var nextIns;
      try {
        nextIns = pc.add(4).readU32();
      } catch (e) {
        continue;
      }
      if ((nextIns & 0xffc00000) !== 0x91000000) continue;
      var addImm = (nextIns >> 10) & 0xfff;
      if (addImm !== strOff) continue;

      // Verify register chain
      var adrpRd = ins & 0x1f;
      var addRn = (nextIns >> 5) & 0x1f;
      if (adrpRd !== addRn) continue;

      // This function references our string!
      return funcStart;
    }
  }

  return null;
}

// ─── Hook system libssl.so ───────────────────────────────────────────────────

(function () {
  var libssl = Process.findModuleByName("libssl.so");
  if (libssl) {
    hookSslModule(libssl, "libssl");
  }
})();

// ─── Hook BoringSSL in libflutter.so ─────────────────────────────────────────

(function () {
  var libflutter = Process.findModuleByName("libflutter.so");
  if (!libflutter) return;

  // Tier 1: Try exported symbols (debug builds)
  var exportSyms = ["SSL_write", "SSL_read"];
  var foundWrite = false,
    foundRead = false;

  var addr = libflutter.findExportByName("SSL_write");
  if (addr) {
    foundWrite = hookSslFunction(addr, "flutter:SSL_write", "ssl_write");
  }
  addr = libflutter.findExportByName("SSL_read");
  if (addr) {
    foundRead = hookSslFunction(addr, "flutter:SSL_read", "ssl_read");
  }

  if (foundWrite && foundRead) return;

  send({
    type: "hook_info",
    label: "flutter-boringssl",
    msg: "No exported SSL symbols — scanning for stripped BoringSSL (ARM64)...",
  });

  // Find the string addresses first
  var sslWriteStr = null;
  var sslReadStr = null;

  // Memory.scan is async; we need to use scanSync for sequential logic
  try {
    var writeMatches = Memory.scanSync(
      libflutter.base,
      libflutter.size,
      "53 53 4c 5f 77 72 69 74 65 00",
    ); // "SSL_write\0"
    if (writeMatches.length > 0) sslWriteStr = writeMatches[0].address;

    var readMatches = Memory.scanSync(
      libflutter.base,
      libflutter.size,
      "53 53 4c 5f 72 65 61 64 00",
    ); // "SSL_read\0"
    if (readMatches.length > 0) sslReadStr = readMatches[0].address;
  } catch (e) {
    send({
      type: "hook_error",
      label: "flutter-string-scan",
      error: e.message,
    });
    return;
  }

  if (!sslWriteStr && !sslReadStr) {
    send({
      type: "hook_info",
      label: "flutter-boringssl",
      msg: "No BoringSSL strings found in libflutter.so — not a Flutter app or custom SSL",
    });
    return;
  }

  send({
    type: "hook_info",
    label: "flutter-boringssl",
    msg:
      "Strings found: " +
      (sslWriteStr ? "SSL_write@" + sslWriteStr + " " : "") +
      (sslReadStr ? "SSL_read@" + sslReadStr : ""),
  });

  // Tier 2: ADRP+ADD xref resolution
  if (!foundWrite && sslWriteStr) {
    var writeFunc = resolveByAdrpXref(libflutter, sslWriteStr);
    if (writeFunc) {
      send({
        type: "hook_info",
        label: "flutter-boringssl",
        msg: "SSL_write resolved via ADRP xref → " + writeFunc,
      });
      foundWrite = hookSslFunction(
        writeFunc,
        "flutter:SSL_write(xref)",
        "ssl_write",
      );
    }
  }

  if (!foundRead && sslReadStr) {
    var readFunc = resolveByAdrpXref(libflutter, sslReadStr);
    if (readFunc) {
      send({
        type: "hook_info",
        label: "flutter-boringssl",
        msg: "SSL_read resolved via ADRP xref → " + readFunc,
      });
      foundRead = hookSslFunction(
        readFunc,
        "flutter:SSL_read(xref)",
        "ssl_read",
      );
    }
  }

  if (foundWrite && foundRead) return;

  // Tier 3: Prologue pattern scan (heuristic fallback)
  if (!foundWrite && sslWriteStr) {
    send({
      type: "hook_info",
      label: "flutter-boringssl",
      msg: "ADRP xref failed for SSL_write, trying prologue pattern scan...",
    });
    var writeFunc2 = findByProloguePattern(
      libflutter,
      sslWriteStr,
      "SSL_write",
    );
    if (writeFunc2) {
      send({
        type: "hook_info",
        label: "flutter-boringssl",
        msg: "SSL_write resolved via prologue scan → " + writeFunc2,
      });
      foundWrite = hookSslFunction(
        writeFunc2,
        "flutter:SSL_write(prologue)",
        "ssl_write",
      );
    }
  }

  if (!foundRead && sslReadStr) {
    var readFunc2 = findByProloguePattern(libflutter, sslReadStr, "SSL_read");
    if (readFunc2) {
      send({
        type: "hook_info",
        label: "flutter-boringssl",
        msg: "SSL_read resolved via prologue scan → " + readFunc2,
      });
      foundRead = hookSslFunction(
        readFunc2,
        "flutter:SSL_read(prologue)",
        "ssl_read",
      );
    }
  }

  if (!foundWrite && !foundRead) {
    send({
      type: "hook_info",
      label: "flutter-boringssl",
      msg:
        "Could not resolve SSL_write/SSL_read in stripped libflutter.so. " +
        "Consider using reFlutter to patch the APK: apkre patch --apk app.apk",
    });
  }
})();

// ─── Java OkHttp hooks ──────────────────────────────────────────────────────

// Defer Java hooks — Java.performNow fails in attach mode on Flutter apps
setTimeout(function () {
  try {
    Java.perform(function () {
      try {
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");

        RealCall.execute.implementation = function () {
          var resp = this.execute();
          try {
            var req = this.request();
            var url = req.url().toString();
            var method = req.method();
            var code = resp.code();
            var msg = {
              type: "okhttp",
              method: method,
              url: url,
              status: code,
            };

            // Safely read response body via peekBody (does NOT consume the stream)
            try {
              var peeked = resp.peekBody(65536);
              var bodyStr = peeked.string();
              if (bodyStr && bodyStr.length > 0) {
                msg.response_body = bodyStr.substring(0, 16384);
              }
            } catch (e) {}

            // Read request body if present
            try {
              var reqBody = req.body();
              if (reqBody !== null) {
                var Buffer = Java.use("okio.Buffer");
                var buf = Buffer.$new();
                reqBody.writeTo(buf);
                var reqStr = buf.readUtf8();
                if (reqStr && reqStr.length > 0) {
                  msg.request_body = reqStr.substring(0, 16384);
                }
              }
            } catch (e) {}

            send(msg);

            // Extract auth header
            try {
              var authHeader = req.header("Authorization");
              if (authHeader) {
                send({ type: "token", value: authHeader });
              }
            } catch (e) {}
          } catch (e) {}
          return resp;
        };

        // Also hook enqueue for async calls
        try {
          RealCall.enqueue.implementation = function (callback) {
            try {
              var req = this.request();
              var url = req.url().toString();
              var method = req.method();
              send({ type: "okhttp", method: method, url: url, status: 0 });
            } catch (e) {}
            this.enqueue(callback);
          };
        } catch (e) {}

        send({ type: "hook_ok", label: "okhttp3" });
      } catch (e) {
        // OkHttp not present — expected for Flutter apps
        send({
          type: "hook_info",
          label: "okhttp3",
          msg: "OkHttp not available: " + e,
        });
      }
    });
  } catch (e) {
    send({
      type: "hook_info",
      label: "okhttp3",
      msg: "Java not ready (attach mode): " + e,
    });
  }
}, 2000);

// ─── Heap token scan ────────────────────────────────────────────────────────

setTimeout(function () {
  try {
    Java.perform(function () {
      Java.choose("java.lang.String", {
        onMatch: function (s) {
          try {
            var val = s.toString();
            if (val && val.length > 20 && val.startsWith("eyJ")) {
              send({ type: "token", value: val });
            }
            if (val && val.toLowerCase().indexOf("bearer ") === 0) {
              send({ type: "token", value: val });
            }
          } catch (e) {}
        },
        onComplete: function () {},
      });
    });
  } catch (e) {}
}, 5000);

send({ type: "agent_ready" });
