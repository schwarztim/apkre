"""Extract URL patterns and auth strings from decompiled APK source."""
from __future__ import annotations

import re
from pathlib import Path

# URL pattern: http(s):// followed by non-whitespace/quote chars
_URL_RE = re.compile(
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%{}|\\^`<>]+'
)

# Path template patterns like /v1/user/{id}
_PATH_RE = re.compile(
    r'"(/(?:v\d+/)?[a-z][a-zA-Z0-9_\-/{}]+)"'
)

# Auth header patterns
_AUTH_RE = re.compile(
    r'(?i)(Authorization|Bearer|X-Token|X-Api-Key|api[_-]key|access[_-]token|'
    r'x-auth-token|x-user-token|token)["\s:=]+([^\s"\'\\]{8,})',
)

# JWT-like tokens
_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')


class StringScanner:
    """Recursively scan decompiled source for URLs, paths, and auth patterns."""

    _EXTENSIONS = {".java", ".kt", ".smali", ".xml", ".json", ".yaml", ".yml", ".txt", ".js"}

    def __init__(self, unpacked_dir: Path) -> None:
        self.root = unpacked_dir

    def scan(self) -> list[dict]:
        endpoints: list[dict] = []
        seen_paths: set[str] = set()

        for path in self._iter_source_files():
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue

            # Full URLs
            for m in _URL_RE.finditer(text):
                url = m.group(0).rstrip(".,;\"')")
                parsed = _parse_url(url)
                if parsed and parsed["path"] not in seen_paths:
                    seen_paths.add(parsed["path"])
                    endpoints.append({**parsed, "source": "static-url", "method": "GET", "auth": False})

            # Path-only templates (needs pairing with host from surrounding context)
            for m in _PATH_RE.finditer(text):
                path_val = m.group(1)
                path_lower = path_val.lower()
                if (len(path_val) > 3
                    and path_val not in seen_paths
                    and not any(path_lower.startswith(p) for p in _NOISE_PATH_PREFIXES)):
                    seen_paths.add(path_val)
                    endpoints.append({
                        "path": path_val,
                        "host": "",
                        "source": "static-path",
                        "method": "?",
                        "auth": _has_nearby_auth(text, m.start()),
                    })

        return endpoints

    def _iter_source_files(self):
        for f in self.root.rglob("*"):
            if f.is_file() and f.suffix in self._EXTENSIONS:
                yield f


_NOISE_HOSTS = {
    # XML/standards namespaces
    "schemas.xmlsoap.org", "www.w3.org", "ns.adobe.com", "purl.org",
    "xmlpull.org", "xml.org", "xmlns.com", "docs.oasis-open.org",
    "iptc.org", "www.editeur.org",
    # Android/Google SDK docs
    "developer.android.com", "developers.google.com", "play.google.com",
    "maven.apache.org", "firebase.google.com", "cloud.google.com",
    "firebaseinstallations.googleapis.com", "accounts.google.com",
    # Library/project pages
    "github.com", "github.io", "gitlab.com", "bitbucket.org",
    "sourceforge.net", "youtrack.jetbrains.com",
    # Reference/docs sites
    "en.wikipedia.org", "www.loc.gov", "www.ecma-international.org",
    "www.iso.org", "tools.ietf.org", "www.iana.org",
    "www.nationalarchives.gov.uk", "www.openarchives.org",
    "fileformats.archiveteam.org", "justsolve.archiveteam.org",
    "www.fileformat.info", "www.verypdf.com", "www.sno.phy.queensu.ca",
    # SDK/framework hosts
    "apache.org", "tika.apache.org", "crashlytics.com",
    "www.microsoft.com", "docs.microsoft.com", "msdn.microsoft.com",
    "developer.apple.com", "fsf.org", "www.gnu.org",
    "earth.google.com", "gcmd.gsfc.nasa.gov", "mpgedit.org",
    # Facebook SDK
    "www.facebook.com", "graph.facebook.com", "facebook.com",
    # Sentry / analytics
    "sentry.io",
    # Telemetry / analytics
    "event.bblmw.com", "ip-api.com",
    "firebaselogging-pa.googleapis.com",
    "app-measurement.com", "analytics.google.com",
    # Additional SDK/spec hosts
    "www.opengl.org", "www.khronos.org", "registry.khronos.org",
    "json-schema.org", "json-ld.org", "schema.org",
    "www.w3.org", "www.rfc-editor.org",
    "creativecommons.org", "www.apache.org",
    "logging.apache.org", "commons.apache.org",
    "square.github.io", "jakewharton.github.io",
    "google.github.io", "bumptech.github.io",
    "developer.mozilla.org",
    "www.freedesktop.org",
    "www.ietf.org",
    # Certificate / OCSP / CRL infrastructure
    "ocsp.digicert.com", "ocsp.pki.goog", "crl.pki.goog",
    "ocsp.sectigo.com", "crl.sectigo.com",
    "ocsp.verisign.com", "crl.verisign.com",
    "pki.google.com", "crls.pki.goog",
    # XML/schema namespace hosts
    "schemas.android.com", "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    # URL shorteners / examples
    "goo.gl", "bit.ly", "www.example.com", "example.com",
    # IETF / standards
    "datatracker.ietf.org",
    # Android system
    "www.google.com", "google.com",
    "connectivitycheck.gstatic.com",
    "clients1.google.com", "clients3.google.com",
    "www.gstatic.com", "fonts.gstatic.com",
    "fonts.googleapis.com", "mtalk.google.com",
    "android.googleapis.com",
}

_NOISE_PATH_PREFIXES = [
    # Documentation/source links
    "/wiki/", "/html/rfc", "/docs/", "/issues/", "/blob/", "/pull/",
    "/licenses/", "/reference/", "/guide/", "/training/",
    "/en-US/", "/en-us/",
    # Android system paths (root detection strings, not APIs)
    "/proc/", "/sys/", "/dev/", "/data/local/", "/data/misc/",
    "/system/bin/", "/system/xbin/", "/system/sd/",
    "/sbin/", "/su/", "/apk/res",
    "/Android/data/", "/android_asset/",
    "/storage/", "/sdcard/", "/mnt/",
    "/cpufreq/", "/cmdline",
    # XML/metadata namespace paths
    "/xap/", "/xmp/", "/exif/", "/tiff/", "/pdf/",
    "/dc/", "/ns/", "/rss/", "/atom/", "/kml/",
    "/ldf/", "/std/", "/onix/", "/xml/", "/xslt",
    "/sax/", "/property/", "/feature/",
    "/namespaces/", "/namespace",
    "/envelope/", "/encoding/",
    "/DRM/", "/LA_URL",
    "/office/", "/officeDocument/", "/wordprocessingml/", "/package/",
    # Media/spec paths
    "/emsg/", "/streaming/", "/guidelines/",
    "/speed/", "/camera-raw/", "/photoshop/",
    # SDK/framework paths
    "/pagead/", "/custom_audience", "/dialog/",
    "/deployment/", "/platforms/", "/packages/",
    "/specs/", "/src/artifact",
    "/interop/", "/preservation/", "/publications/",
    "/marc/", "/staging/",
    "/rec/", "/rfc/",
    "/kms/docs/",
    "/o/oauth2/",
    # Catch-all short noise
    "/a", "/s", "/>", "/%s",
    "/fd/", "/raw/", "/scaled_",
    "/thumbnail_", "/file_picker",
    "/10", "/20",  # year-like path segments from embedded docs
    # OCSP/CRL/cert paths
    "/ocsp", "/crl/", "/pki/", "/ca/", "/cert/",
    # Schema/spec paths
    "/draft/", "/draft-", "/json-schema/",
    "/vocab/", "/schema/",
    # Common non-API resource paths
    "/static/", "/assets/", "/images/", "/fonts/",
    "/css/", "/js/", "/media/",
]


def _parse_url(url: str) -> dict | None:
    """Parse a URL into host + path dict, filtering non-API URLs."""
    m = re.match(r'https?://([^/?\s#]+)(/[^?\s#]*)?(\?[^\s#]*)?', url)
    if not m:
        return None
    host = m.group(1)
    path = m.group(2) or "/"
    query = m.group(3) or ""

    # Filter noise hosts (SDKs, specs, docs)
    host_lower = host.lower()
    if host_lower in _NOISE_HOSTS:
        return None
    if any(host_lower.endswith(f".{nh}") for nh in _NOISE_HOSTS):
        return None

    # Filter noise paths
    path_lower = path.lower()
    if any(path_lower.startswith(p) for p in _NOISE_PATH_PREFIXES):
        return None

    # Filter static resources and docs
    noise_extensions = [".png", ".jpg", ".gif", ".woff", ".ttf", ".css", ".js",
                        ".html", ".htm", ".pdf", ".aspx", ".shtml", ".mspx"]
    if any(path_lower.endswith(ext) for ext in noise_extensions):
        return None

    # Filter tika:link references, XML closing tags, etc.
    if "</tika:" in url or "</url>" in url or "</_" in url:
        return None

    # Filter malformed hosts (must be valid domain-like with real TLD)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)+$', host):
        return None
    # Filter placeholder/example hostnames
    tld = host.rsplit(".", 1)[-1].lower()
    if tld in {"url", "local", "internal", "invalid", "test", "localhost"}:
        return None

    return {"host": host, "path": path, "query": query}


def _has_nearby_auth(text: str, pos: int, window: int = 500) -> bool:
    """Check if auth-related keywords appear near a given position."""
    snippet = text[max(0, pos - window): pos + window]
    return bool(_AUTH_RE.search(snippet))
