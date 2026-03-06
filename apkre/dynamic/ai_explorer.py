"""AI-driven dynamic app exploration via vision LLM + adb.

Supports Azure OpenAI (GPT-4o) and Anthropic (Claude Sonnet) as vision backends.
Priority: Azure OpenAI → Anthropic → error.

Azure credentials are read from macOS Keychain (service: azure-openai) or env vars
(AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT). Anthropic uses ANTHROPIC_API_KEY.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from xml.etree import ElementTree

try:
    from openai import AzureOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

AI_AVAILABLE = OPENAI_AVAILABLE or ANTHROPIC_AVAILABLE

from rich.console import Console


def _keychain_get(service: str, account: str) -> str | None:
    """Read a value from macOS Keychain. Returns None on failure."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True, text=True, timeout=5,
        )
        val = result.stdout.strip()
        return val if val and result.returncode == 0 else None
    except Exception:
        return None

_SYSTEM_PROMPT = """\
You are an API reverse engineer. You are navigating an Android app to discover and catalog \
every backend API endpoint. You see a screenshot, UI hierarchy, and a LIVE LIST of captured \
API endpoints that updates as you trigger network calls.

YOUR GOAL: Maximize the number of unique API endpoints captured. Every tap, scroll, and \
form submission should be chosen to trigger a NEW backend call.

HIGH-VALUE ACTIONS (do these first):
1. Login/auth flows → triggers auth endpoints (token, refresh, user profile)
2. Pull-to-refresh on lists → triggers list/feed endpoints
3. Tap into detail views → triggers GET /resource/{id} endpoints
4. Submit forms (search, create, edit) → triggers POST/PUT endpoints
5. Delete/remove actions → triggers DELETE endpoints
6. Settings/profile → triggers config, preferences, feature-flag endpoints
7. Pagination (scroll to bottom of lists) → triggers ?page=2 / ?offset= endpoints
8. Toggle switches/checkboxes → triggers PATCH/PUT settings endpoints
9. Push notification/inbox → triggers notification endpoints
10. Refresh/retry after errors → may reveal error-handling endpoints

LOW-VALUE ACTIONS (avoid unless nothing else works):
- Scrolling through static content with no list items
- Re-visiting screens you've already been to
- Tapping decorative/non-interactive elements

HANDLE THESE AUTOMATICALLY:
- Permission dialogs: "Allow" / "While using the app"
- Cookie/GDPR: "Accept"
- Update prompts: "Later" / "Skip"
- Login: use test@example.com / TestPass123! or try "Skip"/"Guest"

UNCAPTURED TARGETS are paths found in the APK binary via static analysis. Prioritize \
actions that trigger these endpoints — they represent known API surface not yet exercised.

ANALYZE the captured endpoints list to identify gaps:
- If you see GET /users but no POST /users → try to create something
- If you see /v1/devices/list but no /v1/devices/{id} → tap into a device detail
- If you see auth endpoints but no profile → navigate to profile/settings
- If you see only GET endpoints → look for forms, create buttons, edit icons

Respond with ONLY a JSON object:
{"action": "tap", "x": 360, "y": 640, "reason": "Open device detail to trigger GET /devices/{id}"}
{"action": "swipe", "direction": "up", "reason": "Scroll printer list to trigger pagination"}
{"action": "type", "text": "query", "reason": "Search to trigger search API"}
{"action": "back", "reason": "Return to try a different section"}
{"action": "done", "reason": "Exhausted all discoverable API surfaces"}
"""


class AiExplorer:
    """Use vision LLM to autonomously navigate an Android app."""

    def __init__(
        self,
        device: str,
        package: str,
        console: Console,
        max_iterations: int = 50,
        stale_threshold: int = 8,
        timeout: int = 300,
        static_endpoints: list[dict] | None = None,
    ) -> None:
        self.device = device
        self.package = package
        self.console = console
        self.max_iterations = max_iterations
        self.stale_threshold = stale_threshold
        self.timeout = timeout
        self.static_endpoints = static_endpoints or []
        self._visited_hashes: set[str] = set()
        self._same_screen_count = 0
        self._last_hash: str | None = None
        self._backend: str | None = None
        self._client = None
        self._tried_last_resort = False

    def _init_client(self) -> bool:
        """Initialize the best available vision LLM backend."""
        # Try Azure OpenAI first
        if OPENAI_AVAILABLE:
            api_key = _keychain_get("azure-openai", "api-key") or os.environ.get("AZURE_OPENAI_API_KEY")
            endpoint = _keychain_get("azure-openai", "api-base") or os.environ.get("AZURE_OPENAI_ENDPOINT")
            if api_key and endpoint:
                client = AzureOpenAI(
                    api_key=api_key,
                    azure_endpoint=endpoint.rstrip("/"),
                    api_version="2024-10-21",
                )
                # Verify connectivity with a tiny test call (retry on transient 401)
                for _retry in range(3):
                    try:
                        client.chat.completions.create(
                            model="qrg-gpt4o-experimental",
                            max_tokens=1,
                            messages=[{"role": "user", "content": "hi"}],
                        )
                        self._client = client
                        self._backend = "azure-openai"
                        self.console.print("  [green]✓[/green] AI backend: Azure OpenAI (GPT-4o)")
                        return True
                    except Exception as e:
                        if _retry < 2 and ("401" in str(e) or "429" in str(e)):
                            self.console.print(f"  [dim]Azure retry {_retry+1}/3 ({e.__class__.__name__})...[/dim]")
                            time.sleep(3 * (_retry + 1))
                            continue
                        self.console.print(f"  [yellow]![/yellow] Azure OpenAI failed: {e}")
                        self.console.print("  [dim]Falling back to Anthropic...[/dim]")
                        break

        # Fall back to Anthropic
        if ANTHROPIC_AVAILABLE:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if api_key:
                self._client = anthropic.Anthropic()
                self._backend = "anthropic"
                self.console.print(f"  [green]✓[/green] AI backend: Anthropic (Claude Sonnet)")
                return True

        self.console.print("[red]No AI backend available. Set AZURE_OPENAI_API_KEY or ANTHROPIC_API_KEY.[/red]")
        self.console.print("[dim]Or: pip install openai && store key in Keychain (service: azure-openai)[/dim]")
        return False

    def explore(self, endpoint_feed: callable) -> None:
        """Main exploration loop.

        Args:
            endpoint_feed: callable returning list[dict] of captured endpoints so far
                           (each dict has method, host, path, status, source keys)
        """
        if not AI_AVAILABLE:
            self.console.print("[red]No AI SDK installed. Run: pip install openai  or  pip install anthropic[/red]")
            return

        if not self._init_client():
            return

        self._start_time = time.time()
        deadline = self._start_time + self.timeout
        stale_count = 0
        last_ep_count = 0
        self._conversation: list[dict] = []  # rolling conversation history

        anr_count = 0
        screenshot_fail_count = 0

        for i in range(1, self.max_iterations + 1):
            if time.time() > deadline:
                self.console.print(f"  [yellow]AI: Timeout reached after {i-1} iterations[/yellow]")
                break

            # Capture state
            screenshot_b64, hierarchy_xml = self._capture_state()
            if not screenshot_b64:
                screenshot_fail_count += 1
                if screenshot_fail_count >= 3:
                    self.console.print("  [red]AI: Screenshot failed 3x — giving up[/red]")
                    break
                self.console.print("  [yellow]AI: Screenshot failed — relaunching app[/yellow]")
                self._relaunch_app()
                time.sleep(3)
                continue
            screenshot_fail_count = 0

            # Auto-dismiss ANR dialogs
            if self._is_anr_dialog(hierarchy_xml):
                anr_count += 1
                self.console.print(f"  [yellow]AI: ANR dialog detected ({anr_count}) — dismissing[/yellow]")
                self._shell("input keyevent KEYCODE_BACK")
                time.sleep(2)
                if anr_count >= 6:
                    self.console.print("  [red]AI: App keeps ANR-ing after relaunch — giving up[/red]")
                    break
                if anr_count >= 3:
                    self.console.print("  [yellow]AI: 3 consecutive ANRs — force-stopping and relaunching[/yellow]")
                    self._shell(f"am force-stop {self.package}")
                    time.sleep(1)
                    self._shell(f"am start -n $(cmd package resolve-activity --brief {self.package} | tail -1)")
                    time.sleep(2)
                continue

            # Track visited screens
            screen_hash = self._hash_hierarchy(hierarchy_xml)
            self._visited_hashes.add(screen_hash)

            # Check if we left the app
            if self._is_outside_app(hierarchy_xml):
                self.console.print("  [yellow]AI: Left the app — relaunching[/yellow]")
                self._relaunch_app()
                time.sleep(3)
                self._same_screen_count = 0
                continue

            # Stuck detection
            if screen_hash == self._last_hash:
                self._same_screen_count += 1
                if self._same_screen_count >= 5:
                    self.console.print("  [yellow]AI: Stuck — restarting main activity[/yellow]")
                    self._relaunch_app()
                    self._same_screen_count = 0
                    time.sleep(3)
                    continue
                elif self._same_screen_count >= 3:
                    self.console.print("  [yellow]AI: Same screen 3x — forcing back[/yellow]")
                    self._shell("input keyevent KEYCODE_BACK")
                    time.sleep(1)
                    continue
            else:
                self._same_screen_count = 0
            self._last_hash = screen_hash

            # Get live captured endpoints
            captured = endpoint_feed()
            current_ep_count = len(captured)

            # Stale endpoint detection
            if current_ep_count > last_ep_count:
                stale_count = 0
                last_ep_count = current_ep_count
            else:
                stale_count += 1

            if stale_count >= self.stale_threshold:
                if not self._tried_last_resort:
                    self._tried_last_resort = True
                    self.console.print(
                        f"  [yellow]AI: {self.stale_threshold} stale iterations — relaunching app for one more round[/yellow]"
                    )
                    self._relaunch_app()
                    time.sleep(3)
                    stale_count = self.stale_threshold // 2
                    continue
                self.console.print(
                    f"  [yellow]AI: {self.stale_threshold} iterations with no new endpoints (2nd time) — stopping[/yellow]"
                )
                break

            # Build endpoint summary for the LLM
            endpoint_summary = self._format_endpoint_summary(captured)

            # Log uncaptured targets once for visibility
            if i == 1 and self.static_endpoints:
                captured_paths = {ep.get("path", "") for ep in captured}
                uncaptured = sorted({
                    ep.get("path", "/") for ep in self.static_endpoints
                    if ep.get("path", "") not in captured_paths
                })
                if uncaptured:
                    self.console.print(f"  [dim]AI: {len(uncaptured)} UNCAPTURED TARGETS from static scan[/dim]")
                    for p in uncaptured[:10]:
                        self.console.print(f"  [dim]    {p}[/dim]")

            # Ask LLM for next action (with endpoint context + conversation history)
            compressed_hierarchy = self._compress_hierarchy(hierarchy_xml)
            action = self._decide_action(
                screenshot_b64, compressed_hierarchy,
                i, len(self._visited_hashes), current_ep_count,
                endpoint_summary,
            )
            if not action:
                self.console.print("  [red]AI: Failed to get action from LLM[/red]")
                continue

            if action.get("action") == "done":
                if current_ep_count < 5 and i < self.max_iterations // 2:
                    self.console.print(f"  [yellow]AI: Ignoring early 'done' — only {current_ep_count} endpoints[/yellow]")
                    action = {"action": "swipe", "direction": "up", "reason": "Force scroll to find more content"}
                else:
                    self.console.print(f"  [green]AI: Done — {action.get('reason', 'exploration complete')}[/green]")
                    break

            # Execute
            reason = action.get("reason", "")
            self.console.print(
                f"  [cyan]AI [{i}/{self.max_iterations}][/cyan] "
                f"{action['action']}  {reason}  "
                f"[dim](screens={len(self._visited_hashes)} eps={current_ep_count})[/dim]"
            )
            self._execute_action(action)
            time.sleep(2)  # Wait for network calls to complete

    def _format_endpoint_summary(self, endpoints: list[dict]) -> str:
        """Format captured endpoints as a compact summary for the LLM."""
        if not endpoints:
            return "No API endpoints captured yet. Focus on triggering network requests."

        lines = [f"CAPTURED ENDPOINTS ({len(endpoints)} total):"]
        # Group by host
        by_host: dict[str, list[dict]] = {}
        for ep in endpoints:
            host = ep.get("host", "unknown")
            by_host.setdefault(host, []).append(ep)

        for host, eps in sorted(by_host.items()):
            lines.append(f"\n  {host}:")
            for ep in eps:
                method = ep.get("method", "?")
                path = ep.get("path", "/")
                status = ep.get("status", "")
                status_str = f" → {status}" if status else ""
                auth = " [AUTH]" if ep.get("auth") else ""
                lines.append(f"    {method:6s} {path}{status_str}{auth}")

        # Show uncaptured static targets
        if self.static_endpoints:
            captured_paths = {ep.get("path", "") for ep in endpoints}
            uncaptured = [
                ep.get("path", "/") for ep in self.static_endpoints
                if ep.get("path", "") not in captured_paths
            ]
            # Deduplicate
            uncaptured = sorted(set(uncaptured))
            if uncaptured:
                lines.append(f"\nUNCAPTURED TARGETS (found in APK binary, not yet triggered):")
                for p in uncaptured[:20]:
                    lines.append(f"    {p}")
                if len(uncaptured) > 20:
                    lines.append(f"    ... and {len(uncaptured) - 20} more")

        # Keep it concise — truncate if too many
        result = "\n".join(lines)
        if len(result) > 3000:
            result = result[:3000] + "\n    ... (truncated)"
        return result

    def _capture_state(self) -> tuple[str | None, str]:
        """Take screenshot + dump UI hierarchy."""
        with tempfile.TemporaryDirectory() as tmp:
            remote_png = "/sdcard/apkre_screen.png"
            local_png = Path(tmp) / "screen.png"

            # Use exec-out (works with SELinux enforcing, unlike shell screencap)
            try:
                result = subprocess.run(
                    ["adb", "-s", self.device, "exec-out", "screencap", "-p"],
                    capture_output=True, timeout=10,
                )
                if result.stdout and len(result.stdout) > 100:
                    local_png.write_bytes(result.stdout)
            except subprocess.TimeoutExpired:
                pass

            if not local_png.exists() or local_png.stat().st_size == 0:
                return None, ""

            # Resize to 720px width to save tokens
            self._resize_image(local_png)

            screenshot_b64 = base64.b64encode(local_png.read_bytes()).decode()

            # UI hierarchy
            remote_xml = "/sdcard/apkre_ui.xml"
            self._shell(f"uiautomator dump {remote_xml}")
            local_xml = Path(tmp) / "ui.xml"
            self._adb("pull", remote_xml, str(local_xml))

            hierarchy = local_xml.read_text() if local_xml.exists() else ""

        return screenshot_b64, hierarchy

    def _resize_image(self, path: Path) -> None:
        """Resize image to 720px width. Uses sips on macOS, PIL fallback."""
        try:
            subprocess.run(
                ["sips", "-Z", "720", str(path)],
                capture_output=True, timeout=10,
            )
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            from PIL import Image
            img = Image.open(path)
            ratio = 720 / img.width
            img = img.resize((720, int(img.height * ratio)))
            img.save(path)
        except ImportError:
            pass  # Skip resize, use full image

    def _is_anr_dialog(self, xml: str) -> bool:
        """Detect ANR 'app isn't responding' dialog."""
        if not xml:
            return False
        return ("isn't responding" in xml
                or "isn\\'t responding" in xml
                or "aerr_close" in xml
                or "aerr_wait" in xml)

    def _hash_hierarchy(self, xml: str) -> str:
        """MD5 hash of hierarchy with bounds stripped for normalization."""
        normalized = re.sub(r'bounds="[^"]*"', '', xml)
        return hashlib.md5(normalized.encode()).hexdigest()

    def _compress_hierarchy(self, xml: str) -> str:
        """Strip non-interactive nodes, keep only useful attributes."""
        if not xml.strip():
            return "<hierarchy/>"

        try:
            root = ElementTree.fromstring(xml)
        except ElementTree.ParseError:
            return xml[:3000]

        keep_attrs = {
            "class", "text", "content-desc", "resource-id",
            "clickable", "scrollable", "bounds", "checked",
        }
        interactive_classes = {
            "android.widget.Button", "android.widget.ImageButton",
            "android.widget.EditText", "android.widget.CheckBox",
            "android.widget.Switch", "android.widget.TextView",
            "android.widget.ImageView", "android.widget.ToggleButton",
            "android.widget.Spinner", "android.widget.SeekBar",
            "android.view.View", "android.widget.LinearLayout",
            "android.widget.FrameLayout", "android.widget.ScrollView",
            "android.widget.RecyclerView", "android.widget.ListView",
            "android.widget.TabWidget",
        }

        def is_interactive(elem):
            return (
                elem.get("clickable") == "true"
                or elem.get("scrollable") == "true"
                or elem.get("class", "") in interactive_classes
                or elem.get("text", "").strip()
                or elem.get("content-desc", "").strip()
            )

        lines = []

        def walk(elem, depth=0):
            if not is_interactive(elem) and not any(is_interactive(c) for c in elem.iter()):
                return
            attrs = {k: v for k, v in elem.attrib.items() if k in keep_attrs and v}
            if attrs:
                attr_str = " ".join(f'{k}="{v}"' for k, v in attrs.items())
                lines.append(f"{'  ' * depth}<{elem.tag} {attr_str}/>")
            for child in elem:
                walk(child, depth + 1)

        walk(root)
        result = "\n".join(lines)
        # Truncate if too long
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        return result

    def _decide_action(
        self,
        screenshot_b64: str,
        hierarchy: str,
        iteration: int,
        visited_count: int,
        endpoint_count: int,
        endpoint_summary: str,
    ) -> dict | None:
        """Ask vision LLM to decide the next action with full endpoint context."""
        user_text = (
            f"Iteration {iteration}/{self.max_iterations}. "
            f"Visited {visited_count} unique screens. "
            f"Time remaining: {max(0, int(self._start_time + self.timeout - time.time()))}s\n\n"
            f"{endpoint_summary}\n\n"
            f"UI Hierarchy:\n```xml\n{hierarchy}\n```\n\n"
            f"Based on the captured endpoints and current screen, what action will trigger NEW API calls? "
            f"Respond with JSON only."
        )

        try:
            if self._backend == "azure-openai":
                text = self._call_azure(screenshot_b64, user_text)
            else:
                text = self._call_anthropic(screenshot_b64, user_text)

            # Track conversation for context (text-only summaries to save tokens)
            self._conversation.append({
                "role": "user",
                "content": f"[Iter {iteration}] {endpoint_count} eps. What next?"
            })
            self._conversation.append({"role": "assistant", "content": text})
            # Keep last 6 exchanges
            if len(self._conversation) > 12:
                self._conversation = self._conversation[-12:]

            # Strip markdown code fences if present
            text = re.sub(r'^```(?:json)?\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
            text = text.strip()

            # Try direct parse first
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass

            # Extract first JSON object from response
            obj_match = re.search(r'\{[^{}]*\}', text)
            if obj_match:
                try:
                    return json.loads(obj_match.group())
                except json.JSONDecodeError:
                    pass

            # Last resort: regex extraction of action fields
            action_m = re.search(r'"action"\s*:\s*"(\w+)"', text)
            if action_m:
                result = {"action": action_m.group(1)}
                for field in ("x", "y"):
                    fm = re.search(rf'"{field}"\s*:\s*(\d+)', text)
                    if fm:
                        result[field] = int(fm.group(1))
                dir_m = re.search(r'"direction"\s*:\s*"(\w+)"', text)
                if dir_m:
                    result["direction"] = dir_m.group(1)
                reason_m = re.search(r'"reason"\s*:\s*"([^"]*)"', text)
                if reason_m:
                    result["reason"] = reason_m.group(1)
                return result

            self.console.print(f"  [red]AI: Unparseable response: {text[:100]}[/red]")
            return None
        except Exception as e:
            self.console.print(f"  [red]AI: LLM error: {e}[/red]")
            return None

    def _call_azure(self, screenshot_b64: str, user_text: str) -> str:
        """Call Azure OpenAI GPT-4o with vision + conversation history."""
        # Build messages: system + recent history + current screenshot
        messages = [{"role": "system", "content": _SYSTEM_PROMPT}]

        # Add recent conversation history (text-only, no old images to save tokens)
        for msg in self._conversation[-8:]:
            messages.append(msg)

        messages.append({
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/png;base64,{screenshot_b64}",
                        "detail": "low",
                    },
                },
                {"type": "text", "text": user_text},
            ],
        })

        response = self._client.chat.completions.create(
            model="qrg-gpt4o-experimental",
            max_tokens=300,
            messages=messages,
        )
        return response.choices[0].message.content.strip()

    def _call_anthropic(self, screenshot_b64: str, user_text: str) -> str:
        """Call Anthropic Claude Sonnet with vision + conversation history."""
        # Build messages with recent history + current screenshot
        messages = []

        # Add recent conversation history (text-only)
        for msg in self._conversation[-8:]:
            messages.append(msg)

        messages.append({
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": screenshot_b64,
                    },
                },
                {"type": "text", "text": user_text},
            ],
        })

        response = self._client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            system=_SYSTEM_PROMPT,
            messages=messages,
        )
        return response.content[0].text.strip()

    def _execute_action(self, action: dict) -> None:
        """Execute an adb action."""
        act = action.get("action")

        if act == "tap":
            x, y = action.get("x", 0), action.get("y", 0)
            self._shell(f"input tap {x} {y}")

        elif act == "swipe":
            direction = action.get("direction", "up")
            cx, cy = 360, 640
            swipes = {
                "up": (cx, cy + 300, cx, cy - 300),
                "down": (cx, cy - 300, cx, cy + 300),
                "left": (cx + 300, cy, cx - 300, cy),
                "right": (cx - 300, cy, cx + 300, cy),
            }
            x1, y1, x2, y2 = swipes.get(direction, swipes["up"])
            self._shell(f"input swipe {x1} {y1} {x2} {y2} 300")

        elif act == "type":
            text = action.get("text", "")
            # Escape special characters for adb shell input
            escaped = text.replace(" ", "%s").replace("&", "\\&").replace("<", "\\<").replace(">", "\\>")
            self._shell(f"input text '{escaped}'")

        elif act == "back":
            self._shell("input keyevent KEYCODE_BACK")

        elif act == "keyevent":
            key = action.get("key", "KEYCODE_BACK")
            self._shell(f"input keyevent {key}")

    def _relaunch_app(self) -> None:
        """Force-stop and relaunch the app's main activity."""
        self._shell(f"am force-stop {self.package}")
        time.sleep(1)
        activity = self._shell(
            f"cmd package resolve-activity --brief {self.package} | tail -1"
        )
        if activity:
            self._shell(f"am start -n {activity}")

    def _is_outside_app(self, xml: str) -> bool:
        """Detect if the current foreground is NOT our app (e.g. launcher, settings)."""
        if not xml:
            return False
        # Check if the hierarchy contains our package name
        if self.package in xml:
            return False
        # Common launcher/system indicators
        launcher_hints = [
            "com.android.launcher",
            "com.google.android.apps.nexuslauncher",
            "org.lineageos.trebuchet",
            "com.android.settings",
            "com.android.systemui",
        ]
        return any(hint in xml for hint in launcher_hints)

    def _adb(self, *args: str, timeout: int = 15) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["adb", "-s", self.device, *args],
            capture_output=True, text=True, timeout=timeout,
        )

    def _shell(self, cmd: str, timeout: int = 15) -> str:
        return self._adb("shell", cmd, timeout=timeout).stdout.strip()
