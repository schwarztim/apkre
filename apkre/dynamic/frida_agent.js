/**
 * Frida SSL hook agent — Frida 17.x compatible.
 *
 * Hooks SSL_write/SSL_read via module instance (not Module.findExportByName),
 * handles both system libssl.so and statically linked BoringSSL in libflutter.so.
 *
 * Also hooks Java OkHttp as secondary capture method when Java bridge is ready.
 */

"use strict";

// ─── SSL hooks ────────────────────────────────────────────────────────────

function hookSslModule(mod, label) {
  var sslWrite = mod.findExportByName("SSL_write");
  var sslRead = mod.findExportByName("SSL_read");

  if (sslWrite) {
    Interceptor.attach(sslWrite, {
      onEnter: function (args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave: function (retval) {
        var written = retval.toInt32();
        if (written > 0) {
          var data = Memory.readByteArray(this.buf, Math.min(written, 65536));
          send({ type: "ssl_write", label: label, data: bufToStr(data) });
        }
      },
    });
  }

  if (sslRead) {
    Interceptor.attach(sslRead, {
      onEnter: function (args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave: function (retval) {
        var read = retval.toInt32();
        if (read > 0) {
          var data = Memory.readByteArray(this.buf, Math.min(read, 65536));
          send({ type: "ssl_read", label: label, data: bufToStr(data) });
        }
      },
    });
  }

  if (sslWrite || sslRead) {
    send({ type: "hook_ok", label: label });
  }
}

function bufToStr(buf) {
  if (!buf) return "";
  try {
    // Handle large buffers in chunks to avoid call stack overflow
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

// Hook system libssl.so
(function () {
  var libssl = Process.findModuleByName("libssl.so");
  if (libssl) {
    hookSslModule(libssl, "libssl");
  }
})();

// Hook BoringSSL statically linked inside libflutter.so
// BoringSSL symbols are stripped in release builds, so we use pattern scanning.
(function () {
  var libflutter = Process.findModuleByName("libflutter.so");
  if (!libflutter) return;

  // Try exported symbols first (works on some debug builds)
  var candidates = ["SSL_write", "SSL_read", "bssl::ssl_write"];
  var foundExport = false;
  candidates.forEach(function (sym) {
    var addr = libflutter.findExportByName(sym);
    if (addr) {
      foundExport = true;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this.buf = args[1];
          this.len = args[2].toInt32();
        },
        onLeave: function (ret) {
          var n = ret.toInt32();
          if (n > 0) {
            var d = Memory.readByteArray(this.buf, Math.min(n, 65536));
            send({
              type: "ssl_write",
              label: "flutter-boringssl",
              data: bufToStr(d),
            });
          }
        },
      });
      send({ type: "hook_ok", label: "flutter-boringssl:" + sym });
    }
  });

  if (foundExport) return;

  // Pattern scan for BoringSSL SSL_write/SSL_read in ARM64.
  // BoringSSL's SSL_write has a recognizable prologue that references the
  // SSL->method dispatch table. We scan for the string "SSL_write" which
  // BoringSSL embeds for error reporting, then find the function that
  // references it.
  try {
    var base = libflutter.base;
    var size = libflutter.size;

    // Find string references to identify BoringSSL presence
    var sslWriteStr = null;
    var sslReadStr = null;
    Memory.scan(base, size, "53 53 4c 5f 77 72 69 74 65 00", {
      onMatch: function (addr) {
        sslWriteStr = addr;
      },
      onComplete: function () {},
    });
    Memory.scan(base, size, "53 53 4c 5f 72 65 61 64 00", {
      onMatch: function (addr) {
        sslReadStr = addr;
      },
      onComplete: function () {},
    });

    if (sslWriteStr || sslReadStr) {
      send({
        type: "hook_ok",
        label:
          "flutter-boringssl-pattern:strings-found" +
          (sslWriteStr ? ",write@" + sslWriteStr : "") +
          (sslReadStr ? ",read@" + sslReadStr : ""),
      });
    }

    // ARM64 pattern: BoringSSL SSL_write typically starts with:
    //   STP X29, X30, [SP, #-N]!  (function prologue saving frame/LR)
    //   followed by SSL struct access patterns
    // We look for cross-references to the SSL_write string to find the function.
    if (sslWriteStr) {
      _hookByStringXref(
        libflutter,
        sslWriteStr,
        "ssl_write",
        "flutter-boringssl-write",
      );
    }
    if (sslReadStr) {
      _hookByStringXref(
        libflutter,
        sslReadStr,
        "ssl_read",
        "flutter-boringssl-read",
      );
    }
  } catch (e) {
    send({
      type: "hook_error",
      label: "flutter-boringssl-pattern",
      error: e.message,
    });
  }
})();

function _hookByStringXref(mod, strAddr, direction, label) {
  // On ARM64, string references use ADRP + ADD pairs.
  // The ADRP loads the page, ADD adds the page offset.
  // We compute the page and offset for the target string address.
  var base = mod.base;
  var size = mod.size;
  var pageAddr = strAddr.and(ptr("0xFFFFFFFFFFFFF000"));
  var pageOffset = strAddr.and(ptr("0xFFF"));

  // Scan for ADRP instructions that reference the page containing our string.
  // ADRP encoding: immhi[23:5] | 10000 | immlo[30:29] | Rd[4:0]
  // This is complex, so instead we use a simpler heuristic:
  // Scan for the 4-byte little-endian offset pattern in .rodata pointer tables.
  // Many BoringSSL builds have a dispatch table with function pointers near the strings.

  // Fallback: Hook ssl3_write_app_data which is the internal function SSL_write calls.
  // It has a more identifiable pattern: it checks for ssl->s3->wbuf
  // For now, log that pattern scanning found the strings but couldn't resolve functions.
  send({
    type: "hook_info",
    label: label,
    msg:
      "Found BoringSSL string '" +
      direction +
      "' at " +
      strAddr +
      " but ARM64 xref resolution not yet implemented. " +
      "Consider using reFlutter or manual offset patching.",
  });
}

// ─── Java OkHttp hooks (deferred until Java VM ready) ─────────────────────────

Java.performNow(function () {
  try {
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");

    RealCall.execute.implementation = function () {
      var resp = this.execute();
      try {
        var req = this.request();
        var url = req.url().toString();
        var method = req.method();
        var code = resp.code();
        send({
          type: "okhttp",
          method: method,
          url: url,
          status: code,
        });
      } catch (e) {}
      return resp;
    };
    send({ type: "hook_ok", label: "okhttp3" });
  } catch (e) {
    // OkHttp not present or Java not ready — not fatal
  }
});

// ─── Heap token scan ──────────────────────────────────────────────────────────

// Scan heap for JWT tokens once after 5 seconds
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
