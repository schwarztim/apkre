"""Deduplicate and parameterize discovered endpoints."""
from __future__ import annotations

import re
from collections import defaultdict


# Patterns that look like path parameters: UUIDs, numeric IDs, hashes
_PARAM_RE = re.compile(
    r'(?<=/)'
    r'('
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'  # UUID
    r'|[0-9]{4,}'          # pure numeric ID
    r'|[A-Z0-9]{8,}'       # uppercase device serial / hash
    r')'
    r'(?=/|$)'
)

# Telemetry/analytics hosts to drop during merge
_NOISE_HOSTS = {
    "event.bblmw.com", "ip-api.com",
    "firebaseinstallations.googleapis.com",
    "firebaselogging-pa.googleapis.com",
    "app-measurement.com", "graph.facebook.com",
    "analytics.google.com", "crashlytics.com", "sentry.io",
}


class EndpointMerger:
    """Merge, deduplicate, and parameterize a list of raw endpoint dicts."""

    def __init__(self, endpoints: list[dict]) -> None:
        self.endpoints = endpoints

    def merge(self) -> list[dict]:
        """Return deduplicated, parameterized endpoints."""
        # Normalize paths and filter noise
        normalized: list[dict] = []
        for ep in self.endpoints:
            host = ep.get("host", "").lower()
            if host in _NOISE_HOSTS:
                continue
            ep = dict(ep)
            ep["path"] = _parameterize(ep.get("path", "/"))
            ep["method"] = ep.get("method", "GET").upper()
            if ep["method"] == "?":
                ep["method"] = "GET"
            normalized.append(ep)

        # Deduplicate by (method, host, path), merging bodies from multiple captures
        key_map: dict[str, dict] = {}
        body_map: dict[str, list] = defaultdict(list)
        resp_map: dict[str, list] = defaultdict(list)

        for ep in normalized:
            key = f"{ep['method']}:{ep.get('host','')}:{ep['path']}"
            if key not in key_map:
                key_map[key] = ep
            else:
                # Merge: prefer captures with actual data
                existing = key_map[key]
                if not existing.get("auth") and ep.get("auth"):
                    existing["auth"] = True
                if not existing.get("status") and ep.get("status"):
                    existing["status"] = ep["status"]

            if ep.get("request_body"):
                body_map[key].append(ep["request_body"])
            if ep.get("response_body"):
                resp_map[key].append(ep["response_body"])

        # Attach merged body samples
        for key, ep in key_map.items():
            bodies = body_map[key]
            resps = resp_map[key]
            if bodies:
                ep["request_body"] = bodies[0]
                ep["request_body_samples"] = bodies
            if resps:
                ep["response_body"] = resps[0]
                ep["response_body_samples"] = resps

        merged = list(key_map.values())
        return self._correlate_hosts(merged)

    def _correlate_hosts(self, endpoints: list[dict]) -> list[dict]:
        """Assign hosts to hostless endpoints by correlating with known host-bearing endpoints."""
        # Find dominant host by frequency
        host_freq: dict[str, int] = defaultdict(int)
        for ep in endpoints:
            h = ep.get("host", "")
            if h:
                host_freq[h] += 1

        if not host_freq:
            return endpoints

        dominant_host = max(host_freq, key=host_freq.__getitem__)

        # Index: parameterized path → endpoint with known host
        path_to_hosted: dict[str, dict] = {}
        for ep in endpoints:
            if ep.get("host"):
                path_to_hosted[ep["path"]] = ep

        # Correlate hostless endpoints
        result: list[dict] = []
        for ep in endpoints:
            if ep.get("host"):
                result.append(ep)
                continue

            hosted = path_to_hosted.get(ep["path"])
            if hosted:
                # Merge into existing host-bearing endpoint
                if not hosted.get("auth") and ep.get("auth"):
                    hosted["auth"] = True
                if ep.get("request_body") and not hosted.get("request_body"):
                    hosted["request_body"] = ep["request_body"]
                if ep.get("response_body") and not hosted.get("response_body"):
                    hosted["response_body"] = ep["response_body"]
                # Skip adding — merged into hosted
            else:
                # Unique path: assign dominant host
                ep["host"] = dominant_host
                result.append(ep)

        return result


    @staticmethod
    def service_map(endpoints: list[dict], captured_paths: set[str] | None = None) -> dict[str, dict]:
        """Group endpoints by service prefix (first 2 path segments after version).

        Returns: {service_name: {"total": N, "captured": M, "paths": [...]}}
        """
        services: dict[str, dict] = {}
        for ep in endpoints:
            parts = [p for p in ep.get("path", "/").strip("/").split("/") if p]
            # Skip version prefix (v1, v2, etc.)
            if parts and re.match(r'^v\d+', parts[0]):
                parts = parts[1:]
            service = parts[0] if parts else "root"
            if service.startswith("{"):
                service = "root"

            if service not in services:
                services[service] = {"total": 0, "captured": 0, "paths": []}
            services[service]["total"] += 1
            services[service]["paths"].append(ep.get("path", "/"))

        if captured_paths:
            for svc, info in services.items():
                info["captured"] = sum(1 for p in info["paths"] if p in captured_paths)

        return services


def _parameterize(path: str) -> str:
    """Replace concrete IDs in path with {param} placeholders."""
    parts = path.split("/")
    result = []
    for part in parts:
        m = re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            r'|[0-9]{4,}'
            r'|[A-Z0-9]{10,}',
            part,
        )
        if m:
            result.append("{id}")
        else:
            result.append(part)
    return "/".join(result)
