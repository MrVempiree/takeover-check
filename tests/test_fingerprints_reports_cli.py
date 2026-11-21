"""Dataset integrity, report rendering and CLI tests for takeover-check."""

import json

import pytest

from takeover_check import checker, cli, report
from takeover_check.checker import Result
from takeover_check.fingerprints import load_fingerprints, match_service

FPS = load_fingerprints()


# --- dataset -------------------------------------------------------------------

def test_dataset_has_expected_size():
    assert len(FPS) >= 14


def test_dataset_entries_are_complete():
    for entry in FPS:
        assert entry.service
        assert entry.cname_suffixes
        assert isinstance(entry.nxdomain_vulnerable, bool)
        # every service must be detectable somehow
        assert entry.http_fingerprints or entry.nxdomain_vulnerable


def test_dataset_services_unique():
    services = [e.service for e in FPS]
    assert len(services) == len(set(services))


def test_dataset_covers_well_known_services():
    services = {e.service for e in FPS}
    for expected in ["GitHub Pages", "Heroku", "Amazon S3", "Shopify",
                     "Netlify", "Vercel", "Microsoft Azure"]:
        assert expected in services


def test_match_service_suffix_matching():
    assert match_service("user.github.io", FPS).service == "GitHub Pages"
    assert match_service("shop.myshopify.com", FPS).service == "Shopify"
    assert match_service("x.herokudns.com", FPS).service == "Heroku"
    assert match_service("bucket.s3.amazonaws.com", FPS).service == "Amazon S3"


def test_match_service_trailing_dot_and_case():
    assert match_service("User.GitHub.IO.", FPS).service == "GitHub Pages"


def test_match_service_no_match():
    assert match_service("hosting-provider.net", FPS) is None


def test_fingerprint_body_matching():
    entry = match_service("user.github.io", FPS)
    assert entry.match_body("...There isn't a GitHub Pages site here...") \
        == "There isn't a GitHub Pages site here"
    assert entry.match_body("a perfectly normal page") is None


# --- reports ---------------------------------------------------------------------

def sample_result(status="vulnerable"):
    return Result(subdomain="blog.example.com", cname="user.github.io",
                  service="GitHub Pages", status=status,
                  evidence="signature matched",
                  remediation="Remove the dangling DNS record.")


def test_json_report_counts():
    data = json.loads(report.to_json([sample_result(),
                                      sample_result("claimed")]))
    assert data["tool"] == "takeover-check"
    assert data["checked"] == 2
    assert data["vulnerable"] == 1


def test_markdown_report_table_and_remediation():
    md = report.to_markdown([sample_result()])
    assert "| blog.example.com |" in md
    assert "VULNERABLE" in md
    assert "Remove the dangling DNS record." in md


def test_markdown_report_empty():
    assert "No subdomains were checked" in report.to_markdown([])


def test_terminal_report_summary_line():
    out = report.to_terminal([sample_result(), sample_result("unknown")])
    assert "2 checked, 1 vulnerable." in out


# --- CLI ---------------------------------------------------------------------------

class FakeResolver:
    def cname(self, host):
        return {"blog.example.com": "user.github.io"}.get(host)

    def resolves(self, host):
        return True


def fake_http(host):
    return 404, "There isn't a GitHub Pages site here."


def patch_dns(monkeypatch):
    monkeypatch.setattr(checker, "SystemResolver", FakeResolver)
    monkeypatch.setattr(checker, "http_get", fake_http)


def test_cli_detects_vulnerable_and_exits_1(monkeypatch, capsys):
    patch_dns(monkeypatch)
    code = cli.main(["blog.example.com"])
    assert code == 1
    assert "VULNERABLE" in capsys.readouterr().out


def test_cli_no_fail_flag(monkeypatch):
    patch_dns(monkeypatch)
    assert cli.main(["blog.example.com", "--no-fail"]) == 0


def test_cli_json_format(monkeypatch, capsys):
    patch_dns(monkeypatch)
    cli.main(["blog.example.com", "--format", "json", "--no-fail"])
    data = json.loads(capsys.readouterr().out)
    assert data["vulnerable"] == 1


def test_cli_subdomains_from_file(monkeypatch, tmp_path, capsys):
    patch_dns(monkeypatch)
    f = tmp_path / "subs.txt"
    f.write_text("# comment\nblog.example.com\n", encoding="utf-8")
    code = cli.main(["--file", str(f), "--no-fail"])
    assert code == 0
    assert "blog.example.com" in capsys.readouterr().out


def test_cli_no_targets_errors():
    with pytest.raises(SystemExit):
        cli.main([])
