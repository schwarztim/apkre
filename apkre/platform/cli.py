"""CLI subcommands for apkre emulator farm management."""
from __future__ import annotations

import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from apkre.platform.config import PlatformConfig
from apkre.platform.avd_provisioner import AvdProvisioner
from apkre.platform.lifecycle import LifecycleManager, AvdStatus
from apkre.platform.vnc_manager import VncManager

platform_app = typer.Typer(name="platform", help="Emulator farm management.")
console = Console()


@platform_app.command()
def provision(
    count: int = typer.Option(10, "--count", "-n"),
    start_id: int = typer.Option(1, "--start-id"),
    seed: int = typer.Option(42, "--seed"),
) -> None:
    """Provision AVD instances."""
    cfg = PlatformConfig()
    prov = AvdProvisioner(cfg)
    for i in range(start_id, start_id + count):
        console.print(f"  Provisioning AVD {i:03d}...")
        prov.create(instance_id=i, seed=seed)
        console.print(f"  [green]done[/green]")
    console.print(f"[green]Provisioned {count} AVDs[/green]")


@platform_app.command()
def start(
    instance_id: int = typer.Option(None, "--id"),
    all_instances: bool = typer.Option(False, "--all"),
) -> None:
    """Start AVD instance(s)."""
    cfg = PlatformConfig()
    mgr = LifecycleManager(cfg)
    if all_instances:
        prov = AvdProvisioner(cfg)
        for inst in prov.list_instances():
            pid = mgr.start(inst["id"])
            console.print(f"  AVD {inst['id']:03d} started (PID {pid})")
    elif instance_id:
        pid = mgr.start(instance_id)
        console.print(f"AVD {instance_id:03d} started (PID {pid})")
    else:
        console.print("[red]Specify --id or --all[/red]")
        raise typer.Exit(1)


@platform_app.command()
def stop(
    instance_id: int = typer.Option(None, "--id"),
    all_instances: bool = typer.Option(False, "--all"),
) -> None:
    """Stop AVD instance(s)."""
    cfg = PlatformConfig()
    mgr = LifecycleManager(cfg)
    if all_instances:
        for iid, st in mgr.status_all().items():
            if st == AvdStatus.RUNNING:
                mgr.stop(iid)
                console.print(f"  AVD {iid:03d} stopped")
    elif instance_id:
        mgr.stop(instance_id)
        console.print(f"AVD {instance_id:03d} stopped")
    else:
        console.print("[red]Specify --id or --all[/red]")
        raise typer.Exit(1)


@platform_app.command()
def status() -> None:
    """Show status of all AVD instances."""
    cfg = PlatformConfig()
    mgr = LifecycleManager(cfg)
    vnc = VncManager(cfg)
    statuses = mgr.status_all()
    if not statuses:
        console.print("No AVD instances found.")
        return
    table = Table(title="apkre Emulator Farm")
    table.add_column("ID", justify="right")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("ADB Port")
    table.add_column("VNC URL")
    for iid, st in sorted(statuses.items()):
        style = {"running": "green", "stopped": "dim", "booting": "yellow", "error": "red"}.get(st.value, "white")
        table.add_row(
            str(iid), f"apkre_{iid:03d}", f"[{style}]{st.value}[/{style}]",
            str(cfg.adb_port(iid)),
            vnc.novnc_url(iid, host="100.111.242.50") if st == AvdStatus.RUNNING else "",
        )
    console.print(table)


@platform_app.command()
def deploy_services(
    count: int = typer.Option(10, "--count", "-n"),
    start_id: int = typer.Option(1, "--start-id"),
) -> None:
    """Generate and install systemd service units."""
    cfg = PlatformConfig()
    mgr = LifecycleManager(cfg)
    vnc = VncManager(cfg)
    for i in range(start_id, start_id + count):
        avd_unit = mgr.generate_systemd_unit(i)
        Path(f"/etc/systemd/system/apkre-avd-{i:03d}.service").write_text(avd_unit)
        vnc_unit = vnc.generate_systemd_unit(i)
        Path(f"/etc/systemd/system/apkre-novnc-{i:03d}.service").write_text(vnc_unit)
        console.print(f"  apkre-avd-{i:03d}.service + apkre-novnc-{i:03d}.service")
    console.print(f"[green]Deployed. Run: sudo systemctl daemon-reload[/green]")


@platform_app.command()
def deploy_nginx(
    count: int = typer.Option(10, "--count", "-n"),
    start_id: int = typer.Option(1, "--start-id"),
) -> None:
    """Generate nginx config and dashboard HTML."""
    cfg = PlatformConfig()
    vnc = VncManager(cfg)
    ids = list(range(start_id, start_id + count))
    nginx = vnc.generate_nginx_config(ids)
    Path("/etc/nginx/sites-available/apkre-farm").write_text(nginx)
    Path("/etc/nginx/sites-enabled/apkre-farm").symlink_to("/etc/nginx/sites-available/apkre-farm")
    html = vnc.generate_dashboard_html(ids, host="100.111.242.50")
    Path("/data/apkre/dashboard/index.html").write_text(html)
    console.print("[green]Nginx config + dashboard deployed. Run: sudo nginx -t && sudo systemctl reload nginx[/green]")


@platform_app.command("root-image")
def root_image(
    system_image: str = typer.Option(
        "/data/android-sdk/system-images/android-31/google_apis/x86_64/ramdisk.img",
        "--image", "-i",
        help="Path to ramdisk.img to patch with Magisk"
    ),
) -> None:
    """Patch system image ramdisk with Magisk using rootAVD."""
    cfg = PlatformConfig()
    rootavd_script = cfg.base_dir / "rootAVD" / "rootAVD.sh"
    if not rootavd_script.exists():
        console.print(f"[red]rootAVD not found at {rootavd_script}[/red]")
        console.print("Clone it with: git clone https://github.com/newbit1/rootAVD.git /data/apkre/rootAVD")
        raise typer.Exit(1)
    if not Path(system_image).exists():
        console.print(f"[red]System image not found: {system_image}[/red]")
        raise typer.Exit(1)
    console.print(f"[yellow]Patching ramdisk with Magisk...[/yellow]")
    console.print(f"  Image: {system_image}")
    console.print("[dim]Select 'Magisk Stable' when prompted[/dim]")
    result = subprocess.run(
        ["bash", str(rootavd_script), system_image],
        cwd=str(rootavd_script.parent),
    )
    if result.returncode == 0:
        console.print("[green]Ramdisk patched successfully![/green]")
        console.print("[dim]All AVDs using this system image will now boot with Magisk.[/dim]")
    else:
        console.print(f"[red]rootAVD failed with exit code {result.returncode}[/red]")
        raise typer.Exit(1)


@platform_app.command("setup-magisk")
def setup_magisk(
    instance_id: int = typer.Option(..., "--id", "-i", help="AVD instance ID"),
    module_zip: str = typer.Option(
        None, "--module", "-m",
        help="Path to Magisk module zip to install"
    ),
) -> None:
    """Install Magisk modules on a running AVD instance."""
    cfg = PlatformConfig()
    mgr = LifecycleManager(cfg)
    if mgr.status(instance_id) != AvdStatus.RUNNING:
        console.print(f"[red]AVD {instance_id:03d} is not running[/red]")
        raise typer.Exit(1)
    port = cfg.adb_port(instance_id)
    serial = f"emulator-{port}"
    # Verify root access
    console.print(f"[yellow]Checking root access on AVD {instance_id:03d}...[/yellow]")
    result = subprocess.run(
        [cfg.adb_binary, "-s", serial, "shell", "su", "-c", "id"],
        capture_output=True, text=True, timeout=30,
    )
    if "uid=0(root)" not in result.stdout:
        console.print("[red]Root access not available. Ensure ramdisk was patched with root-image.[/red]")
        console.print(f"  Output: {result.stdout.strip()}")
        raise typer.Exit(1)
    console.print("[green]Root access verified (uid=0)[/green]")
    if module_zip:
        if not Path(module_zip).exists():
            console.print(f"[red]Module not found: {module_zip}[/red]")
            raise typer.Exit(1)
        console.print(f"[yellow]Installing module: {module_zip}[/yellow]")
        # Push module to device
        subprocess.run(
            [cfg.adb_binary, "-s", serial, "push", module_zip, "/data/local/tmp/module.zip"],
            check=True, timeout=60,
        )
        # Install via Magisk (with manual extraction fallback)
        result = subprocess.run(
            [cfg.adb_binary, "-s", serial, "shell", "su", "-c",
             "magisk --install-module /data/local/tmp/module.zip"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            console.print("[green]Module installed via Magisk. Reboot required.[/green]")
        else:
            console.print("[yellow]Magisk install-module failed, using manual extraction...[/yellow]")
            # Extract module directly to /data/adb/modules/
            mod_id = subprocess.run(
                [cfg.adb_binary, "-s", serial, "shell",
                 "unzip -p /data/local/tmp/module.zip module.prop | grep ^id= | cut -d= -f2"],
                capture_output=True, text=True, timeout=30,
            ).stdout.strip()
            if not mod_id:
                mod_id = "apkre-antidetect"
            subprocess.run(
                [cfg.adb_binary, "-s", serial, "shell",
                 f"rm -rf /data/adb/modules/{mod_id} && mkdir -p /data/adb/modules/{mod_id} && "
                 f"cd /data/adb/modules/{mod_id} && unzip -o /data/local/tmp/module.zip"],
                check=True, timeout=60,
            )
            console.print(f"[green]Module extracted to /data/adb/modules/{mod_id}. Reboot required.[/green]")
    else:
        console.print("[dim]No module specified. Use --module to install a Magisk module.[/dim]")
        console.print("[dim]For property spoofing, install DeviceSpoofLab-Magisk.zip[/dim]")


@platform_app.command("scrcpy-server")
def scrcpy_server(
    port: int = typer.Option(8000, "--port", "-p", help="Port to run ws-scrcpy on"),
    foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground"),
) -> None:
    """Start ws-scrcpy web server for interactive emulator access."""
    cfg = PlatformConfig()
    ws_scrcpy_dir = cfg.base_dir / "ws-scrcpy"
    if not ws_scrcpy_dir.exists():
        console.print(f"[red]ws-scrcpy not found at {ws_scrcpy_dir}[/red]")
        console.print("Clone and build it:")
        console.print("  git clone https://github.com/NetrisTV/ws-scrcpy.git /data/apkre/ws-scrcpy")
        console.print("  cd /data/apkre/ws-scrcpy && npm install && npm run dist")
        raise typer.Exit(1)
    console.print(f"[yellow]Starting ws-scrcpy server on port {port}...[/yellow]")
    console.print(f"  Web UI: http://100.111.242.50:{port}")
    console.print("[dim]All ADB-connected emulators will appear in the device list.[/dim]")
    import os
    env = os.environ.copy()
    env["PORT"] = str(port)
    # Ensure adb is in PATH for ws-scrcpy to spawn adb processes
    adb_path = cfg.android_sdk / "platform-tools"
    env["PATH"] = f"{adb_path}:/usr/bin:/usr/local/bin:{env.get('PATH', '')}"
    if foreground:
        subprocess.run(
            ["npm", "start"],
            cwd=str(ws_scrcpy_dir),
            env=env,
        )
    else:
        log_path = cfg.logs_dir / "ws-scrcpy.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as log:
            proc = subprocess.Popen(
                ["npm", "start"],
                cwd=str(ws_scrcpy_dir),
                stdout=log, stderr=log,
                env=env,
            )
        console.print(f"[green]ws-scrcpy started (PID {proc.pid})[/green]")
        console.print(f"  Logs: {log_path}")


@platform_app.command("build-module")
def build_module(
    output_dir: str = typer.Option(
        "/data/apkre/modules",
        "--output", "-o",
        help="Directory to save the Magisk module zip"
    ),
) -> None:
    """Build the apkre anti-detection Magisk module."""
    from pathlib import Path
    from apkre.platform.anti_detect import AntiDetect

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    console.print("[yellow]Building apkre-antidetect Magisk module...[/yellow]")
    zip_path = AntiDetect.build_magisk_module(out)
    console.print(f"[green]Module built: {zip_path}[/green]")
    console.print(f"[dim]Install with: apkre platform setup-magisk --id N --module {zip_path}[/dim]")


@platform_app.command("apply-hardening")
def apply_hardening(
    instance_id: int = typer.Option(None, "--id", "-i", help="AVD instance ID (or --all)"),
    all_instances: bool = typer.Option(False, "--all", help="Apply to all running AVDs"),
) -> None:
    """Apply anti-detection hardening to running AVD(s).

    Runs the boot-props.sh script which uses resetprop to spoof
    device identity, hides emulator artifacts, and sets battery/sensor state.
    """
    import subprocess
    from apkre.platform.config import PlatformConfig
    from apkre.platform.lifecycle import LifecycleManager, AvdStatus

    cfg = PlatformConfig()
    mgr = LifecycleManager(cfg)

    ids_to_harden = []
    if all_instances:
        for iid, st in mgr.status_all().items():
            if st == AvdStatus.RUNNING:
                ids_to_harden.append(iid)
    elif instance_id:
        ids_to_harden = [instance_id]
    else:
        console.print("[red]Specify --id or --all[/red]")
        raise typer.Exit(1)

    if not ids_to_harden:
        console.print("[yellow]No running AVDs found.[/yellow]")
        return

    for iid in ids_to_harden:
        script = cfg.avd_home(iid) / "boot-props.sh"
        if not script.exists():
            console.print(f"  [yellow]AVD {iid:03d}: no boot-props.sh, re-provisioning...[/yellow]")
            from apkre.platform.avd_provisioner import AvdProvisioner
            prov = AvdProvisioner(cfg)
            prov.create(instance_id=iid, seed=42)
        console.print(f"  [yellow]AVD {iid:03d}: applying hardening...[/yellow]")
        result = subprocess.run(
            ["bash", str(script)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            console.print(f"  [green]AVD {iid:03d}: hardened[/green]")
        else:
            console.print(f"  [red]AVD {iid:03d}: failed — {result.stderr[:200]}[/red]")
