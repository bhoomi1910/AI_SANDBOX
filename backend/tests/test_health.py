def test_health_operational(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "operational"
    assert body["components"]["api"] == "operational"


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["health"] == "/api/health"


def test_dashboard_stats_empty_db(client):
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["totalInvestigations"]["value"] == 0
    assert stats["statusDistribution"] == {}


def test_list_investigations_empty(client):
    resp = client.get("/api/investigations")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_missing_investigation_404(client):
    resp = client.get("/api/investigations/does-not-exist")
    assert resp.status_code == 404
