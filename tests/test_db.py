import db


def test_plain_local_mongodb_does_not_force_tls(monkeypatch):
    monkeypatch.delenv("MONGO_TLS", raising=False)
    monkeypatch.delenv("MONGO_TLS_CERT_FILE", raising=False)

    assert db._mongo_tls_options("mongodb://localhost:27017") == {}


def test_explicit_client_certificate_enables_tls(monkeypatch):
    monkeypatch.delenv("MONGO_TLS", raising=False)
    monkeypatch.setenv("MONGO_TLS_CERT_FILE", "/tmp/client.pem")

    options = db._mongo_tls_options("mongodb://localhost:27017")

    assert options["tls"] is True
    assert options["tlsCertificateKeyFile"] == "/tmp/client.pem"
