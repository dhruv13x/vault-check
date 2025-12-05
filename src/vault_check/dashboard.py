
import json
import os
import aiohttp
import asyncio
from aiohttp import web
import logging

def create_dashboard_app(reports_dir: str, runner_factory=None) -> web.Application:
    app = web.Application()
    app["reports_dir"] = reports_dir
    app["websockets"] = set()
    app["runner_factory"] = runner_factory

    async def broadcast(message):
        for ws in list(app["websockets"]):
            try:
                await ws.send_json(message)
            except Exception:
                app["websockets"].discard(ws)

    app["broadcast"] = broadcast

    app.add_routes([
        web.get('/', handle_index),
        web.get('/ws', handle_websocket),
        web.get('/api/reports', handle_list_reports),
        web.get('/api/reports/{filename}', handle_get_report),
        web.post('/api/run', handle_run_verification),
    ])
    return app

async def handle_websocket(request: web.Request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    request.app["websockets"].add(ws)

    try:
        async for msg in ws:
            pass  # We ignore incoming messages for now, just sending updates
    finally:
        request.app["websockets"].discard(ws)

    return ws

async def handle_run_verification(request: web.Request) -> web.Response:
    runner_factory = request.app.get("runner_factory")
    if not runner_factory:
        return web.json_response({"error": "Verification runner not configured"}, status=501)

    # Run in background
    asyncio.create_task(_run_background_verification(request.app, runner_factory))
    return web.json_response({"status": "started"})

async def _run_background_verification(app, runner_factory):
    try:
        await app["broadcast"]({"type": "status", "message": "Starting verification..."})

        # runner_factory should return (runner, loaded_secrets, version)
        runner, loaded_secrets, version = await runner_factory()

        await runner.run(loaded_secrets, version, event_callback=app["broadcast"])

        await app["broadcast"]({"type": "status", "message": "Verification complete."})
    except Exception as e:
        logging.error(f"Background verification failed: {e}")
        await app["broadcast"]({"type": "error", "message": str(e)})

async def handle_index(request: web.Request) -> web.Response:
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vault Check Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; }
        .container { max-width: 960px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f8f8; font-weight: 600; }
        tr:hover { background-color: #f1f1f1; cursor: pointer; }
        .status-passed { color: green; font-weight: bold; }
        .status-failed { color: red; font-weight: bold; }
        .details-panel { margin-top: 20px; border-top: 2px solid #eee; padding-top: 20px; display: none; }
        .back-btn { display: inline-block; margin-bottom: 10px; cursor: pointer; color: blue; text-decoration: underline; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .error { color: red; }
        .warning { color: orange; }
        #live-status { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; background: #eef; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vault Check Dashboard</h1>
        <button onclick="triggerRun()" style="padding: 10px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; margin-bottom: 20px;">Run Verification Now</button>
        <div id="live-status">
            <h3>Live Verification</h3>
            <div id="live-log"></div>
        </div>
        <div id="report-list">
            <p>Loading reports...</p>
        </div>
        <div id="report-detail" class="details-panel">
            <span class="back-btn" onclick="showList()">← Back to list</span>
            <h2 id="detail-title"></h2>
            <div id="detail-content"></div>
        </div>
    </div>

    <script>
        let ws;

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleLiveUpdate(data);
            };

            ws.onclose = function() {
                // Try to reconnect in 5 seconds
                setTimeout(connectWebSocket, 5000);
            };
        }

        function handleLiveUpdate(data) {
            const liveStatus = document.getElementById('live-status');
            const liveLog = document.getElementById('live-log');
            liveStatus.style.display = 'block';

            if (data.type === 'check_start') {
                 liveLog.innerHTML += `<div>Running: ${data.check}...</div>`;
            } else if (data.type === 'check_complete') {
                 liveLog.innerHTML += `<div>Finished: ${data.check} (${data.status})</div>`;
            } else if (data.type === 'status') {
                 liveLog.innerHTML += `<div><b>${data.message}</b></div>`;
            } else if (data.type === 'error') {
                 liveLog.innerHTML += `<div class="error"><b>Error: ${data.message}</b></div>`;
            }
        }

        async function triggerRun() {
            try {
                const response = await fetch('/api/run', { method: 'POST' });
                const data = await response.json();
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    document.getElementById('live-log').innerHTML = ''; // Clear previous logs
                    alert('Verification started!');
                }
            } catch (e) {
                alert('Failed to trigger verification');
            }
        }

        async function fetchReports() {
            try {
                const response = await fetch('/api/reports');
                const reports = await response.json();
                renderList(reports);
            } catch (e) {
                document.getElementById('report-list').innerHTML = '<p class="error">Failed to load reports.</p>';
            }
        }

        function renderList(reports) {
            if (reports.length === 0) {
                document.getElementById('report-list').innerHTML = '<p>No reports found.</p>';
                return;
            }
            let html = '<table><thead><tr><th>Filename</th><th>Status</th><th>Version</th></tr></thead><tbody>';
            reports.forEach(r => {
                html += `<tr onclick="loadReport('${r.filename}')">
                    <td>${r.filename}</td>
                    <td class="${r.status === 'PASSED' ? 'status-passed' : 'status-failed'}">${r.status}</td>
                    <td>${r.version}</td>
                </tr>`;
            });
            html += '</tbody></table>';
            document.getElementById('report-list').innerHTML = html;
        }

        async function loadReport(filename) {
            try {
                const response = await fetch('/api/reports/' + filename);
                const report = await response.json();
                renderDetail(filename, report);
            } catch (e) {
                alert('Failed to load report');
            }
        }

        function renderDetail(filename, report) {
            document.getElementById('report-list').style.display = 'none';
            document.getElementById('report-detail').style.display = 'block';
            document.getElementById('detail-title').textContent = filename;

            let content = `<h3>Status: <span class="${report.status === 'PASSED' ? 'status-passed' : 'status-failed'}">${report.status}</span></h3>`;
            content += `<p>Version: ${report.version}</p>`;

            if (report.errors && report.errors.length > 0) {
                content += '<h4>Errors</h4><ul>';
                report.errors.forEach(e => content += `<li class="error">${e}</li>`);
                content += '</ul>';
            }

            if (report.warnings && report.warnings.length > 0) {
                content += '<h4>Warnings</h4><ul>';
                report.warnings.forEach(w => content += `<li class="warning">${w}</li>`);
                content += '</ul>';
            }

            content += '<h4>Raw Data</h4><pre>' + JSON.stringify(report, null, 2) + '</pre>';
            document.getElementById('detail-content').innerHTML = content;
        }

        function showList() {
            document.getElementById('report-detail').style.display = 'none';
            document.getElementById('report-list').style.display = 'block';
        }

        fetchReports();
        connectWebSocket();
    </script>
</body>
</html>
    """
    return web.Response(text=html, content_type='text/html')


async def handle_list_reports(request: web.Request) -> web.Response:
    reports_dir = request.app["reports_dir"]
    reports = []

    loop = asyncio.get_event_loop()

    def _read_reports():
        result = []
        if not os.path.exists(reports_dir):
            return result

        for f in os.listdir(reports_dir):
            if f.endswith(".json"):
                path = os.path.join(reports_dir, f)
                try:
                    with open(path, "r") as json_file:
                        data = json.load(json_file)
                        result.append({
                            "filename": f,
                            "status": data.get("status", "UNKNOWN"),
                            "version": data.get("version", "UNKNOWN")
                        })
                except Exception as e:
                    logging.warning(f"Failed to read report {f}: {e}")
        return result

    try:
        reports = await loop.run_in_executor(None, _read_reports)
    except Exception as e:
         logging.error(f"Error listing reports: {e}")
         return web.json_response({"error": str(e)}, status=500)

    return web.json_response(reports)

async def handle_get_report(request: web.Request) -> web.Response:
    filename = request.match_info['filename']
    reports_dir = request.app["reports_dir"]
    path = os.path.join(reports_dir, filename)

    # Security check: prevent directory traversal
    if not os.path.abspath(path).startswith(os.path.abspath(reports_dir)):
         return web.Response(status=403, text="Forbidden")

    def _read_file():
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            return json.load(f)

    loop = asyncio.get_event_loop()
    try:
        data = await loop.run_in_executor(None, _read_file)
        if data is None:
             return web.Response(status=404, text="Report not found")
        return web.json_response(data)
    except Exception as e:
        return web.Response(status=500, text=f"Error reading file: {e}")
