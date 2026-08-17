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


def test_dashboard_stats_valid_structure(client):
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert "summary" in stats
    assert isinstance(stats["summary"]["total"], int)
    assert stats["summary"]["total"] >= 0
    assert stats["statusDistribution"] is not None
    assert stats["note"] != ""


def test_list_investigations_returns_list(client):
    resp = client.get("/api/investigations")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_get_missing_investigation_404(client):
    resp = client.get("/api/investigations/does-not-exist")
    assert resp.status_code == 404
