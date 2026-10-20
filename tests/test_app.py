"""Functional tests -- both the vulnerable and the secure app must pass these."""


def test_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"DevSecOps Demo App" in resp.data


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_user_lookup(client):
    data = client.get("/user?name=alice").get_json()
    assert len(data) == 1
    assert data[0]["email"] == "alice@example.com"


def test_unknown_user(client):
    assert client.get("/user?name=nobody").get_json() == []


def test_greet(client):
    resp = client.get("/greet?name=Jasim")
    assert resp.status_code == 200
    assert b"Hello Jasim!" in resp.data


def test_hash_is_hex(client):
    h = client.get("/hash?pw=secret").get_json()["hash"]
    int(h, 16)


def test_config_yaml(client):
    resp = client.post("/config", data="debug: false\nport: 5000\n")
    assert resp.status_code == 200
    assert "port" in resp.get_json()["loaded"]
