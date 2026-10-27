from eng.notify import Notifier


def test_dry_run_without_config(monkeypatch):
    for k in ("NTFY_TOPIC", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(k, raising=False)
    n = Notifier(background=False)
    assert n.send("t", "b", "high") == ["dry-run"]


def test_ntfy_needs_https(monkeypatch):
    monkeypatch.setenv("NTFY_TOPIC", "x")
    monkeypatch.setenv("NTFY_SERVER", "http://insecure")
    assert Notifier().channels == []


def test_token_never_logged(monkeypatch, caplog):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "SECRETTOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "1")
    n = Notifier(background=False)
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("bot SECRETTOKEN fail")))
    n.send("t", "b", "high")
    assert "SECRETTOKEN" not in caplog.text and "***" in caplog.text
