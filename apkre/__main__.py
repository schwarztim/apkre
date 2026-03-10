"""CLI entry point for apkre."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from apkre.static.apk_unpack import ApkUnpacker
from apkre.static.string_scanner import StringScanner
from apkre.static.dart_scanner import DartScanner
from apkre.dynamic.frida_controller import FridaController
from apkre.dynamic.logcat_tap import LogcatTap
from apkre.dynamic.token_extractor import TokenExtractor
from apkre.analysis.schema_inferrer import SchemaInferrer
from apkre.analysis.endpoint_merger import EndpointMerger
from apkre.output.openapi_builder import OpenApiBuilder
from apkre.output.postman_builder import PostmanBuilder
from apkre.output.curl_builder import CurlBuilder
from apkre.device.prereq_check import PrereqChecker
from apkre.device.setup import DeviceSetup
from apkre.dynamic.ai_explorer import AI_AVAILABLE
from apkre.session import Session
from apkre.platform.cli import platform_app

app = typer.Typer(
    name="apkre",
    help="APK Reverse Engineering Platform — automated API discovery",
    rich_markup_mode="rich",
)
console = Console()


def _resolve_apk(apk: str | None, package: str | None, device: str | None) -> str:
    """Resolve APK path: use provided path, pull from device by package, or pull base.apk."""
    if apk and Path(apk).exists():
        return apk

    if not device:
        if apk:
            console.print(f"[red]APK not found: {apk}[/red]")
        raise typer.Exit(1)

    # Try to find package on device
    pkg = package
    if not pkg and apk:
        # Try to match APK filename to installed package
        pkg = ApkUnpacker.extract_package_name(apk, device=device)
        if pkg == "unknown.package":
            pkg = None

    if not pkg:
        console.print("[red]Cannot resolve APK. Provide --apk (local file) or --package (installed app).[/red]")
        raise typer.Exit(1)

    console.print(f"  [yellow]→[/yellow] Pulling APK from device for {pkg}...")
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pm", "path", pkg],
        capture_output=True, text=True, timeout=10,
    )
    base_path = None
    for line in result.stdout.splitlines():
        remote = line.strip().removeprefix("package:")
        if "base.apk" in remote or "split_" not in remote:
            base_path = remote
            break

    if not base_path:
        console.print(f"[red]Could not find APK path for {pkg} on device[/red]")
        raise typer.Exit(1)

    local_apk = Path(tempfile.gettempdir()) / f"{pkg}_base.apk"
    subprocess.run(
        ["adb", "-s", device, "pull", base_path, str(local_apk)],
        capture_output=True, timeout=60,
    )
    console.print(f"  [green]✓[/green] Pulled {base_path} → {local_apk}")
    return str(local_apk)


def _resolve_device(device: str | None) -> str | None:
    """Auto-detect device if not specified."""
    if device:
        return device
    result = subprocess.run(
        ["adb", "devices"], capture_output=True, text=True, timeout=10,
    )
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            console.print(f"  [dim]Auto-detected device: {parts[0]}[/dim]")
            return parts[0]
    return None


@app.command()
def analyze(
    apk: str = typer.Option(None, "--apk", help="Path to APK file (auto-pulled from device if not provided)"),
    package: str = typer.Option(None, "--package", "-p", help="Package name (e.g. com.example.app)"),
    device: str = typer.Option(None, "--device", help="ADB device serial (default: first connected)"),
    output: str = typer.Option("api-spec.yaml", "--output", "-o", help="Output OpenAPI YAML path"),
    postman: str = typer.Option(None, "--postman", help="Output Postman collection JSON path"),
    curls: str = typer.Option(None, "--curls", help="Output curl command sheet path"),
    static_only: bool = typer.Option(False, "--static-only", help="Skip dynamic capture"),
    dynamic_only: bool = typer.Option(False, "--dynamic-only", help="Skip static analysis"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive capture: press Ctrl+C when done"),
    ai: bool = typer.Option(False, "--ai", help="AI-driven exploration: Claude autonomously navigates the app"),
    timeout: int = typer.Option(300, "--timeout", help="Dynamic capture timeout in seconds"),
    skip_prereqs: bool = typer.Option(False, "--skip-prereqs", help="Skip prerequisite checks"),
) -> None:
    """[bold green]Analyze an APK and produce an OpenAPI specification.[/bold green]

    Runs static analysis (URL/auth extraction) and dynamic capture (Frida SSL hooks,
    logcat tap, mitmproxy) then generates a complete OpenAPI 3.0 spec.
    """
    # Auto-detect device
    device = _resolve_device(device)

    # Resolve APK: local file, or pull from device
    apk_path = _resolve_apk(apk, package, device)

    session = Session(apk_path=apk_path, device=device)

    # If package was explicitly provided, use it
    if package:
        session.package_name = package

    with console.status("[bold blue]Starting apkre analysis...[/bold blue]"):
        if not skip_prereqs:
            checker = PrereqChecker(console)
            checker.check(device=device)

    endpoints: list[dict] = []
    static_endpoints: list[dict] = []

    # -- Static analysis -------------------------------------------------------
    if not dynamic_only:
        console.rule("[bold]Phase 1 — Static Analysis[/bold]")

        unpacker = ApkUnpacker(apk_path, session.work_dir, device=device)
        unpacked = unpacker.unpack()
        console.print(f"  [green]✓[/green] Unpacked to {unpacked}")

        scanner = StringScanner(unpacked)
        static_endpoints = scanner.scan()
        console.print(f"  [green]✓[/green] Found {len(static_endpoints)} URL patterns")

        dart_scanner = DartScanner(unpacked)
        dart_endpoints = dart_scanner.scan()
        console.print(f"  [green]✓[/green] Dart/Flutter scan: {len(dart_endpoints)} additional endpoints")

        static_endpoints = list(static_endpoints) + list(dart_endpoints)
        endpoints.extend(static_endpoints)
        session.save_endpoints(endpoints, source="static")

        # Display service map from static analysis
        svc_map = EndpointMerger.service_map(static_endpoints)
        if svc_map:
            svc_table = Table(title="Service Map (static analysis)")
            svc_table.add_column("Service", style="cyan")
            svc_table.add_column("Paths", style="white", justify="right")
            for svc, info in sorted(svc_map.items(), key=lambda x: -x[1]["total"]):
                svc_table.add_row(svc, str(info["total"]))
            console.print(svc_table)

    # Quick static scan for AI targeting (even in dynamic-only mode)
    if dynamic_only and ai:
        console.print("  [dim]Quick static scan for AI targeting...[/dim]")
        try:
            unpacker = ApkUnpacker(apk_path, session.work_dir, device=device)
            unpacked = unpacker.unpack()
            scanner = StringScanner(unpacked)
            static_endpoints = scanner.scan()
            dart_scanner = DartScanner(unpacked)
            static_endpoints.extend(dart_scanner.scan())
            console.print(f"  [dim]Found {len(static_endpoints)} static paths for AI targeting[/dim]")
            # Display pre-capture service map
            svc_map = EndpointMerger.service_map(static_endpoints)
            if svc_map:
                svc_table = Table(title="Service Map (pre-capture)")
                svc_table.add_column("Service", style="cyan")
                svc_table.add_column("Paths", style="white", justify="right")
                for svc, info in sorted(svc_map.items(), key=lambda x: -x[1]["total"]):
                    svc_table.add_row(svc, str(info["total"]))
                console.print(svc_table)
        except Exception as e:
            console.print(f"  [dim]Static scan skipped: {e}[/dim]")

    # -- Dynamic capture -------------------------------------------------------
    if not static_only and device:
        console.rule("[bold]Phase 2 — Dynamic Capture[/bold]")

        setup = DeviceSetup(device, console)
        setup.save_state()
        setup.register_cleanup()

        try:
            setup.sync_clock()
            setup.fix_routing()

            if not setup.verify_connectivity():
                console.print("  [red]✗[/red] No internet connectivity — try toggling WiFi on device")
                console.print("  [dim]Continuing with capture anyway (logcat may still work)...[/dim]")

            pkg = session.package_name
            if pkg is None:
                pkg = ApkUnpacker.extract_package_name(apk_path, device=device)
                session.package_name = pkg
            console.print(f"  [green]✓[/green] Package: {pkg}")

            if ai:
                # AI-driven exploration: background capture + Claude navigation
                if not AI_AVAILABLE:
                    console.print("[red]No AI SDK installed. Run: pip install openai  or  pip install 'apkre[ai]'[/red]")
                    raise typer.Exit(1)

                from apkre.dynamic.ai_explorer import AiExplorer

                # Wake + dismiss keyguard (no swipe to avoid triggering shortcuts)
                console.print("  [yellow]→[/yellow] Waking device screen...")
                subprocess.run(
                    ["adb", "-s", device, "shell",
                     "input keyevent KEYCODE_WAKEUP && input keyevent KEYCODE_MENU"],
                    capture_output=True, timeout=10,
                )
                time.sleep(1)

                # Ensure SELinux is enforcing (anti-tamper checks this)
                setup._root_shell("setenforce 1")

                # Stop frida-server during app launch (anti-tamper scans for it)
                console.print("  [yellow]→[/yellow] Stopping frida-server for clean app launch...")
                setup._root_shell("pkill -f frida-server || true")
                time.sleep(1)

                # Launch app before Frida attach (needs a running process)
                console.print(f"  [yellow]→[/yellow] Launching {pkg}...")
                resolve_result = subprocess.run(
                    ["adb", "-s", device, "shell", "cmd", "package", "resolve-activity", "--brief", pkg],
                    capture_output=True, text=True, timeout=10,
                )
                activity = resolve_result.stdout.strip().splitlines()[-1] if resolve_result.stdout.strip() else None
                if activity:
                    subprocess.run(
                        ["adb", "-s", device, "shell", "am", "start", "-n", activity],
                        capture_output=True, timeout=10,
                    )
                    time.sleep(5)  # Extra time for anti-tamper to complete

                # Restart frida-server after app init (anti-tamper window passed)
                console.print("  [yellow]→[/yellow] Restarting frida-server...")
                setup._root_shell("/data/local/tmp/frida-server -D &")
                # Poll frida-server readiness (up to 15s)
                for _wait in range(15):
                    try:
                        import frida as _frida_check
                        _dev = _frida_check.get_device(device) if device else _frida_check.get_usb_device()
                        _procs = _dev.enumerate_processes()
                        if any(p.name == pkg for p in _procs):
                            break
                    except Exception:
                        pass
                    time.sleep(1)

                console.print("  [yellow]→[/yellow] Starting background logcat + Frida capture...")
                logcat = LogcatTap(device, console)
                logcat.start()

                frida_ctl = FridaController(device, pkg, console)
                console.print("  [yellow]→[/yellow] Frida SSL hooks (attach mode)...")
                try:
                    frida_ctl.start_background(mode="attach")
                except Exception as e:
                    console.print(f"  [red]✗[/red] Frida background start failed: {e}")
                    console.print("  [dim]Continuing with logcat only...[/dim]")

                def _endpoint_feed():
                    """Live feed of parsed endpoints from logcat + frida."""
                    eps = []
                    # Parse logcat lines on the fly for live feedback
                    eps.extend(logcat._parse_lines(logcat._lines))
                    # Frida endpoints are already parsed
                    eps.extend(frida_ctl._endpoints)
                    return eps

                console.print("  [yellow]→[/yellow] Starting AI exploration...")
                explorer = AiExplorer(
                    device, pkg, console,
                    max_iterations=50,
                    stale_threshold=12,
                    timeout=timeout,
                    static_endpoints=static_endpoints,
                )
                explorer.explore(endpoint_feed=_endpoint_feed)

                # Collect results
                logcat_endpoints = logcat.stop()
                console.print(f"  [green]✓[/green] Logcat: {len(logcat_endpoints)} endpoints")
                endpoints.extend(logcat_endpoints)

                frida_endpoints = frida_ctl.stop_background()
                console.print(f"  [green]✓[/green] Frida: {len(frida_endpoints)} requests captured")
                endpoints.extend(frida_endpoints)
                if frida_ctl.tokens:
                    session.tokens.extend(frida_ctl.tokens)

            else:
                # Standard capture: sequential logcat then frida
                # Logcat tap (fastest for Flutter/Dio apps)
                console.print("  [yellow]→[/yellow] Starting logcat tap...")
                logcat = LogcatTap(device, console)
                logcat_endpoints = logcat.capture(
                    timeout=min(timeout, 120) if interactive else min(timeout, 60),
                    interactive=interactive,
                )
                console.print(f"  [green]✓[/green] Logcat: {len(logcat_endpoints)} endpoints")
                endpoints.extend(logcat_endpoints)

                # Frida SSL hook (universal)
                frida_ctl = FridaController(device, pkg, console)
                frida_mode = "attach" if interactive else "spawn"
                console.print(f"  [yellow]→[/yellow] Frida SSL hooks ({frida_mode} mode)...")
                try:
                    frida_endpoints = frida_ctl.capture(timeout=timeout, mode=frida_mode)
                    console.print(f"  [green]✓[/green] Frida: {len(frida_endpoints)} requests captured")
                    endpoints.extend(frida_endpoints)
                    if frida_ctl.tokens:
                        session.tokens.extend(frida_ctl.tokens)
                except Exception as e:
                    console.print(f"  [red]✗[/red] Frida failed: {e}")
                    console.print("  [dim]Continuing with logcat + static results...[/dim]")

            # Token extraction
            console.print("  [yellow]→[/yellow] Extracting auth tokens...")
            extractor = TokenExtractor(device, pkg, console)
            try:
                tokens = extractor.extract()
                session.tokens.extend(tokens)
                if tokens:
                    console.print(f"  [green]✓[/green] Captured {len(tokens)} token(s)")
                else:
                    console.print("  [yellow]![/yellow] No tokens captured via heap/prefs")
            except Exception as e:
                console.print(f"  [red]✗[/red] Token extraction failed: {e}")

            session.save_endpoints(endpoints, source="dynamic")
        finally:
            console.rule("[dim]Cleanup[/dim]")
            setup.restore_state()
    elif not static_only and not device:
        console.print("[yellow]Warning: no device detected, skipping dynamic capture[/yellow]")

    # -- Schema inference & merging --------------------------------------------
    console.rule("[bold]Phase 3 — Analysis[/bold]")

    merger = EndpointMerger(endpoints)
    merged = merger.merge()
    console.print(f"  [green]✓[/green] Merged to {len(merged)} unique endpoints")

    # Display coverage map (static vs captured)
    if static_endpoints:
        captured_paths = {ep.get("path", "") for ep in merged}
        svc_map = EndpointMerger.service_map(static_endpoints, captured_paths=captured_paths)
        if svc_map:
            cov_table = Table(title="API Coverage (static → captured)")
            cov_table.add_column("Service", style="cyan")
            cov_table.add_column("Total", style="white", justify="right")
            cov_table.add_column("Captured", style="green", justify="right")
            cov_table.add_column("Remaining", style="yellow", justify="right")
            for svc, info in sorted(svc_map.items(), key=lambda x: -x[1]["total"]):
                remaining = info["total"] - info["captured"]
                cov_table.add_row(svc, str(info["total"]), str(info["captured"]), str(remaining))
            console.print(cov_table)

    inferrer = SchemaInferrer()
    for ep in merged:
        if ep.get("response_body"):
            ep["response_schema"] = inferrer.infer(ep["response_body"])
        if ep.get("request_body"):
            ep["request_schema"] = inferrer.infer(ep["request_body"])

    # -- Output generation -----------------------------------------------------
    console.rule("[bold]Phase 4 — Output Generation[/bold]")

    builder = OpenApiBuilder(merged, session)
    spec = builder.build()
    builder.write(output)
    console.print(f"  [green]✓[/green] OpenAPI spec → {output}")

    if postman:
        pb = PostmanBuilder(merged, session)
        pb.write(postman)
        console.print(f"  [green]✓[/green] Postman collection → {postman}")

    if curls:
        cb = CurlBuilder(merged, session)
        cb.write(curls)
        console.print(f"  [green]✓[/green] curl commands → {curls}")

    # -- Summary ---------------------------------------------------------------
    console.rule("[bold green]Complete[/bold green]")
    _print_summary(merged, output, session)


@app.command()
def prereqs(
    device: str = typer.Option(None, "--device", help="ADB device serial"),
    fix: bool = typer.Option(False, "--fix", help="Attempt to fix missing prerequisites"),
) -> None:
    """Check (and optionally fix) prerequisites: adb, frida-server, mitmproxy CA."""
    checker = PrereqChecker(console)
    checker.check(device=device, fix=fix)


@app.command()
def device_setup(
    device: str = typer.Option(..., "--device", help="ADB device serial"),
    proxy_host: str = typer.Option("10.0.0.1", "--proxy-host", help="mitmproxy host"),
    proxy_port: int = typer.Option(8080, "--proxy-port", help="mitmproxy port"),
) -> None:
    """Configure device: clock sync, routing fix, mitmproxy proxy."""
    setup = DeviceSetup(device, console)
    setup.sync_clock()
    setup.fix_routing()
    setup.set_proxy(proxy_host, proxy_port)
    console.print("[green]Device setup complete.[/green]")
    console.print(f"[yellow]Remember:[/yellow] Run [bold]apkre device-cleanup --device {device}[/bold] when done to restore proxy.")


@app.command()
def device_cleanup(
    device: str = typer.Option(..., "--device", help="ADB device serial"),
) -> None:
    """Restore device to clean state: clear proxy, verify connectivity."""
    setup = DeviceSetup(device, console)
    setup.clear_proxy()
    if setup.verify_connectivity():
        console.print("[green]Device restored — connectivity verified.[/green]")
    else:
        console.print("[yellow]Proxy cleared but connectivity check failed — try toggling WiFi.[/yellow]")


@app.command()
def patch(
    apk: str = typer.Option(..., "--apk", help="Path to the APK file to patch"),
    output: str = typer.Option(None, "--output", "-o", help="Output patched APK path"),
    proxy: str = typer.Option("10.0.0.1", "--proxy", help="Proxy IP for traffic redirection"),
    proxy_port: int = typer.Option(8080, "--proxy-port", help="Proxy port"),
) -> None:
    """[bold yellow]Patch a Flutter APK with reFlutter for SSL interception.[/bold yellow]

    Rewrites libflutter.so to disable SSL verification and redirect traffic
    through a proxy. Requires reFlutter and apktool.
    """
    import shutil

    if not shutil.which("reflutter"):
        console.print("[red]reFlutter not found. Install: pip install reflutter[/red]")
        raise typer.Exit(1)

    apk_path = Path(apk)
    if not apk_path.exists():
        console.print(f"[red]APK not found: {apk}[/red]")
        raise typer.Exit(1)

    if not output:
        output = str(apk_path.with_stem(apk_path.stem + "_patched"))

    console.print(f"  [yellow]→[/yellow] Patching {apk_path.name} with reFlutter...")
    console.print(f"  [dim]Proxy: {proxy}:{proxy_port}[/dim]")

    # reFlutter patches libflutter.so to redirect traffic and disable cert verification
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            ["reflutter", str(apk_path)],
            capture_output=True, text=True, timeout=300,
            input=f"{proxy}\n",  # reFlutter prompts for proxy IP
            cwd=tmp,
        )

        if result.returncode != 0:
            console.print(f"[red]reFlutter failed:[/red]\n{result.stderr}")
            raise typer.Exit(1)

        # reFlutter outputs to current dir with "release" in the name
        patched_candidates = list(Path(tmp).glob("*release*.apk"))
        if not patched_candidates:
            patched_candidates = list(Path(tmp).glob("*.apk"))

        if not patched_candidates:
            console.print("[red]reFlutter did not produce a patched APK[/red]")
            console.print(f"[dim]stdout: {result.stdout[:500]}[/dim]")
            raise typer.Exit(1)

        patched = patched_candidates[0]
        shutil.copy2(patched, output)

    console.print(f"  [green]✓[/green] Patched APK → {output}")
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  1. Install: adb install {output}")
    console.print(f"  2. Start mitmproxy: mitmdump -p {proxy_port} --ssl-insecure")
    console.print(f"  3. Run: apkre analyze --apk {output} --interactive")


def _print_summary(endpoints: list[dict], spec_path: str, session: Session) -> None:
    table = Table(title="Discovered Endpoints", show_header=True)
    table.add_column("Method", style="cyan", width=8)
    table.add_column("Host", style="dim", max_width=30)
    table.add_column("Path", style="white")
    table.add_column("Source", style="dim")
    table.add_column("Auth", style="yellow")

    for ep in sorted(endpoints, key=lambda e: (e.get("host", ""), e.get("path", ""))):
        table.add_row(
            ep.get("method", "?").upper(),
            ep.get("host", ""),
            ep.get("path", "?"),
            ep.get("source", "?"),
            "Bearer" if ep.get("auth") else "",
        )

    console.print(table)
    console.print(f"\n[bold]Spec written to:[/bold] {spec_path}")
    if session.tokens:
        console.print(f"[bold]Token(s) captured:[/bold] {len(session.tokens)}")


app.add_typer(platform_app, name="platform")

if __name__ == "__main__":
    app()
