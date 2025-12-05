
import json
import os
import tempfile
import pytest
from aiohttp import web

# We will import the app factory from the implementation file later
# For now we assume it exists
from vault_check.dashboard import create_dashboard_app

@pytest.fixture
def reports_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        # Create some dummy reports
        report1 = {
            "version": "1.0.0",
            "errors": [],
            "warnings": [],
            "status": "PASSED"
        }
        with open(os.path.join(tmpdirname, "report_1.json"), "w") as f:
            json.dump(report1, f)

        report2 = {
            "version": "1.0.0",
            "errors": ["Some error"],
            "warnings": [],
            "status": "FAILED"
        }
        with open(os.path.join(tmpdirname, "report_2.json"), "w") as f:
            json.dump(report2, f)

        yield tmpdirname

@pytest.fixture
async def client(aiohttp_client, reports_dir):
    app = create_dashboard_app(reports_dir)
    return await aiohttp_client(app)

@pytest.mark.asyncio
async def test_dashboard_index(client):
    resp = await client.get("/")
    assert resp.status == 200
    text = await resp.text()
    assert "<title>Vault Check Dashboard</title>" in text

@pytest.mark.asyncio
async def test_list_reports(client):
    resp = await client.get("/api/reports")
    assert resp.status == 200
    data = await resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    filenames = [item["filename"] for item in data]
    assert "report_1.json" in filenames
    assert "report_2.json" in filenames

@pytest.mark.asyncio
async def test_get_report(client):
    resp = await client.get("/api/reports/report_1.json")
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "PASSED"

@pytest.mark.asyncio
async def test_get_report_not_found(client):
    resp = await client.get("/api/reports/nonexistent.json")
    assert resp.status == 404
