"""AI-driven dynamic app exploration via Claude vision + adb."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path
from xml.etree import ElementTree

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from rich.console import Console

_SYSTEM_PROMPT = """\
You are an Android app explorer. Your goal is to systematically discover every API endpoint \
by navigating every screen of the app. You receive a screenshot and compressed UI hierarchy.

Strategy:
- Prioritize: Settings, Profile, Account, Search, Lists, Tabs, Navigation drawers
- Handle permission dialogs: tap "Allow" or "While using the app"
- Handle login forms: type test credentials (test@example.com / TestPass123!)
- Scroll feeds and lists to trigger pagination APIs
- Visit every tab in bottom navigation bars
- Open menus, expand sections, tap into detail screens
- After exhausting a screen, go back and try the next unexplored element
- If stuck on same screen, try swiping or pressing back

Respond with ONLY a JSON object (no markdown, no explanation):
{"action": "tap", "x": 360, "y": 640, "reason": "Tap Settings button"}
{"action": "swipe", "direction": "up", "reason": "Scroll feed to load more"}
{"action": "swipe", "direction": "left", "reason": "Swipe to next tab"}
{"action": "type", "text": "test@example.com", "reason": "Enter email in login form"}
{"action": "back", "reason": "Return to previous screen"}
{"action": "keyevent", "key": "KEYCODE_HOME", "reason": "Go home"}
{"action": "done", "reason": "All screens explored, no new elements to interact with"}

Track which screens you've visited based on the hierarchy. Prefer unexplored interactive elements.
"""


class AiExplorer:
    """Use Claude vision to autonomously navigate an Android app."""

    def __init__(
        self,
        device: str,
        package: str,
        console: Console,
        max_iterations: int = 50,
        stale_threshold: int = 8,
        timeout: int = 300,
    ) -> None:
        self.device = device
        self.package = package
        self.console = console
        self.max_iterations = max_iterations
        self.stale_threshold = stale_threshold
        self.timeout = timeout
        self._visited_hashes: set[str] = set()
        self._same_screen_count = 0
        self._last_hash: str | None = None

    def explore(self, endpoint_counter: callable) -> None:
        """Main exploration loop.

        Args:
            endpoint_counter: callable that returns current endpoint count
        """
        if not ANTHROPIC_AVAILABLE:
            self.console.print("[red]anthropic SDK not installed. Run: pip install anthropic[/red]")
            return

        client = anthropic.Anthropic()
        deadline = time.time() + self.timeout
        stale_count = 0
        last_ep_count = endpoint_counter()

        for i in range(1, self.max_iterations + 1):
            if time.time() > deadline:
                self.console.print(f"  [yellow]AI: Timeout reached after {i-1} iterations[/yellow]")
                break

            # Capture state
            screenshot_b64, hierarchy_xml = self._capture_state()
            if not screenshot_b64:
                self.console.print("  [red]AI: Failed to capture screenshot[/red]")
                break

            # Track visited screens
            screen_hash = self._hash_hierarchy(hierarchy_xml)
            is_new_screen = screen_hash not in self._visited_hashes
            self._visited_hashes.add(screen_hash)

            # Stuck detection: same screen 3x → force back
            if screen_hash == self._last_hash:
                self._same_screen_count += 1
                if self._same_screen_count >= 5:
                    self.console.print("  [yellow]AI: Stuck — restarting main activity[/yellow]")
                    self._shell(f"am start -n $(cmd package resolve-activity --brief {self.package} | tail -1)")
                    self._same_screen_count = 0
                    time.sleep(2)
                    continue
                elif self._same_screen_count >= 3:
                    self.console.print("  [yellow]AI: Same screen 3x — forcing back[/yellow]")
                    self._shell("input keyevent KEYCODE_BACK")
                    time.sleep(1)
                    continue
            else:
                self._same_screen_count = 0
            self._last_hash = screen_hash

            # Stale endpoint detection
            current_ep_count = endpoint_counter()
            if current_ep_count > last_ep_count:
                stale_count = 0
                last_ep_count = current_ep_count
            else:
                stale_count += 1

            if stale_count >= self.stale_threshold:
                self.console.print(
                    f"  [yellow]AI: {self.stale_threshold} iterations with no new endpoints — stopping[/yellow]"
                )
                break

            # Ask Claude for next action
            compressed_hierarchy = self._compress_hierarchy(hierarchy_xml)
            action = self._decide_action(
                client, screenshot_b64, compressed_hierarchy,
                i, len(self._visited_hashes), current_ep_count,
            )
            if not action:
                self.console.print("  [red]AI: Failed to get action from Claude[/red]")
                continue

            if action.get("action") == "done":
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
            time.sleep(1.5)  # Wait for UI to settle

    def _capture_state(self) -> tuple[str | None, str]:
        """Take screenshot + dump UI hierarchy."""
        with tempfile.TemporaryDirectory() as tmp:
            remote_png = "/sdcard/apkre_screen.png"
            local_png = Path(tmp) / "screen.png"

            self._shell(f"screencap -p {remote_png}")
            self._adb("pull", remote_png, str(local_png))

            if not local_png.exists():
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
        client: anthropic.Anthropic,
        screenshot_b64: str,
        hierarchy: str,
        iteration: int,
        visited_count: int,
        endpoint_count: int,
    ) -> dict | None:
        """Ask Claude to decide the next action."""
        user_content = [
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": screenshot_b64,
                },
            },
            {
                "type": "text",
                "text": (
                    f"Iteration {iteration}. "
                    f"Visited {visited_count} unique screens. "
                    f"Discovered {endpoint_count} API endpoints so far.\n\n"
                    f"UI Hierarchy:\n```xml\n{hierarchy}\n```\n\n"
                    f"What action should I take next? Respond with JSON only."
                ),
            },
        ]

        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=256,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_content}],
            )
            text = response.content[0].text.strip()
            # Strip markdown code fences if present
            text = re.sub(r'^```(?:json)?\s*', '', text)
            text = re.sub(r'\s*```$', '', text)
            return json.loads(text)
        except (json.JSONDecodeError, Exception) as e:
            self.console.print(f"  [red]AI: Claude response error: {e}[/red]")
            return None

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

    def _adb(self, *args: str, timeout: int = 15) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["adb", "-s", self.device, *args],
            capture_output=True, text=True, timeout=timeout,
        )

    def _shell(self, cmd: str, timeout: int = 15) -> str:
        return self._adb("shell", cmd, timeout=timeout).stdout.strip()
