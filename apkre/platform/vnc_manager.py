"""noVNC websocket proxy and dashboard management."""
from __future__ import annotations

from apkre.platform.config import PlatformConfig


class VncManager:
    NOVNC_BASE_PORT = 6080
    SCRCPY_PORT = 8000

    def __init__(self, config: PlatformConfig) -> None:
        self.config = config

    def novnc_port(self, instance_id: int) -> int:
        return self.NOVNC_BASE_PORT + instance_id

    def novnc_url(self, instance_id: int, host: str = "localhost") -> str:
        port = self.novnc_port(instance_id)
        return f"http://{host}:{port}/vnc.html?autoconnect=true"

    def scrcpy_url(self, host: str = "localhost") -> str:
        return f"http://{host}:{self.SCRCPY_PORT}"

    def generate_systemd_unit(self, instance_id: int) -> str:
        vnc_port = self.config.vnc_port(instance_id)
        ws_port = self.novnc_port(instance_id)
        name = f"apkre_{instance_id:03d}"
        return f"""[Unit]
Description=noVNC proxy for {name}
After=apkre-avd-{name}.service
BindsTo=apkre-avd-{name}.service

[Service]
Type=simple
User=tim
ExecStart=/usr/bin/websockify --web /usr/share/novnc {ws_port} localhost:{vnc_port}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

    def generate_nginx_config(self, instance_ids: list[int]) -> str:
        locations = "\n".join(self._nginx_location(i) for i in instance_ids)
        return f"""server {{
    listen 8443 ssl;
    server_name _;
    ssl_certificate /data/apkre/config/tls/cert.pem;
    ssl_certificate_key /data/apkre/config/tls/key.pem;

    location / {{
        root /data/apkre/dashboard;
        index index.html;
    }}

    location /api/ {{
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
    }}

    # ws-scrcpy interactive access
    location /scrcpy/ {{
        proxy_pass http://127.0.0.1:{self.SCRCPY_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }}

{locations}
}}
"""

    def _nginx_location(self, instance_id: int) -> str:
        ws_port = self.novnc_port(instance_id)
        return f"""    location /avd/{instance_id}/ {{
        proxy_pass http://127.0.0.1:{ws_port}/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }}
"""

    def generate_dashboard_html(self, instance_ids: list[int], host: str = "localhost") -> str:
        cards = "\n".join(
            f'        <div class="card" id="avd-{i}" onclick="window.open(\'/avd/{i}/vnc.html?autoconnect=true\')">'
            f'\n            <h3>AVD {i:03d}</h3>'
            f'\n            <span class="status" id="status-{i}">unknown</span>'
            f"\n        </div>"
            for i in instance_ids
        )
        scrcpy_url = self.scrcpy_url(host)
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>apkre Emulator Farm</title>
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #0ff; }}
        .header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; }}
        .tools {{ display: flex; gap: 10px; }}
        .tool-btn {{ background: #0a8; color: #fff; border: none; padding: 10px 20px; border-radius: 6px;
                    cursor: pointer; font-family: monospace; font-size: 14px; text-decoration: none; }}
        .tool-btn:hover {{ background: #0c9; }}
        .tool-btn.scrcpy {{ background: #08a; }}
        .tool-btn.scrcpy:hover {{ background: #0ac; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 10px; }}
        .card {{ background: #16213e; border: 1px solid #333; border-radius: 8px; padding: 15px;
                 cursor: pointer; text-align: center; transition: border-color 0.2s; }}
        .card:hover {{ border-color: #0ff; }}
        .status {{ font-size: 12px; padding: 2px 8px; border-radius: 4px; display: inline-block; margin-top: 5px; }}
        .running {{ background: #0a3; color: #fff; }}
        .stopped {{ background: #555; color: #aaa; }}
        .error {{ background: #a00; color: #fff; }}
        .booting {{ background: #a80; color: #fff; }}
        .card-links {{ display: flex; gap: 5px; justify-content: center; margin-top: 8px; }}
        .card-link {{ font-size: 10px; padding: 2px 6px; border-radius: 3px; text-decoration: none; }}
        .card-link.vnc {{ background: #555; color: #fff; }}
        .card-link.scrcpy {{ background: #08a; color: #fff; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>apkre Emulator Farm</h1>
        <div class="tools">
            <a href="{scrcpy_url}" target="_blank" class="tool-btn scrcpy">ws-scrcpy (Interactive)</a>
        </div>
    </div>
    <p id="summary">Loading...</p>
    <div class="grid" id="grid"></div>
    <script>
        const scrcpyUrl = '{scrcpy_url}';
        async function refresh() {{
            try {{
                const r = await fetch('/api/status');
                const d = await r.json();
                const g = document.getElementById('grid');
                g.innerHTML = '';
                let run=0, tot=0;
                for (const [id, info] of Object.entries(d).sort((a,b)=>a[0]-b[0])) {{
                    tot++;
                    if (info.status==='running') run++;
                    const c = document.createElement('div');
                    c.className = 'card';
                    c.innerHTML = '<h3>AVD '+String(id).padStart(3,'0')+'</h3>'
                        + '<span class="status '+info.status+'">'+info.status+'</span>'
                        + (info.app ? '<div style="font-size:11px;color:#888;margin-top:4px">'+info.app+'</div>' : '')
                        + (info.status==='running' ? '<div class="card-links">'
                            + '<a href="/avd/'+id+'/vnc.html?autoconnect=true" target="_blank" class="card-link vnc" onclick="event.stopPropagation()">VNC</a>'
                            + '<a href="'+scrcpyUrl+'" target="_blank" class="card-link scrcpy" onclick="event.stopPropagation()">scrcpy</a>'
                            + '</div>' : '');
                    c.onclick = () => window.open('/avd/'+id+'/vnc.html?autoconnect=true');
                    g.appendChild(c);
                }}
                document.getElementById('summary').textContent = run+'/'+tot+' running';
            }} catch(e) {{
                document.getElementById('summary').textContent = 'API unreachable';
            }}
        }}
        refresh();
        setInterval(refresh, 5000);
    </script>
</body>
</html>
"""
