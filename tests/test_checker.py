"""Classification tests for takeover-check. DNS and HTTP are mocked."""

import pytest

from takeover_check import checker
from takeover_check.fingerprints import load_fingerprints

FPS = load_fingerprints()


class FakeResolver:
    def __init__(self, cnames=None, resolving=None):
        self.cnames = cnames or {}
        self.resolving = resolving or {}

    def cname(self, host):
        return self.cnames.get(host)

    def resolves(self, host):
        return self.resolving.get(host.rstrip("."), True)


def http_returning(body, status=404):
    def _get(host):
        return status, body
    return _get


def check(sub, resolver, http_fn):
    return checker.check_subdomain(sub, resolver, http_fn, FPS)


# --- vulnerable via HTTP fingerprint -----------------------------------------

def test_github_pages_unclaimed_is_vulnerable():
    resolver = FakeResolver({"blog.example.com": "user.github.io"})
    result = check("blog.example.com", resolver,
                   http_returning("There isn't a GitHub Pages site here."))
    assert result.status == "vulnerable"
    assert result.service == "GitHub Pages"
    assert "GitHub Pages" in result.evidence


def test_heroku_deleted_app_is_vulnerable():
    resolver = FakeResolver({"app.example.com": "x.herokudns.com"})
    result = check("app.example.com", resolver,
                   http_returning("<title>No such app</title>"))
    assert result.status == "vulnerable"
    assert result.service == "Heroku"


def test_s3_deleted_bucket_is_vulnerable():
    resolver = FakeResolver({"files.example.com": "files.s3.amazonaws.com"})
    result = check("files.example.com", resolver,
                   http_returning("<Error><Code>NoSuchBucket</Code></Error>"))
    assert result.status == "vulnerable"
    assert result.service == "Amazon S3"


def test_shopify_closed_store_is_vulnerable():
    resolver = FakeResolver({"shop.example.com": "shop.myshopify.com"})
    result = check("shop.example.com", resolver,
                   http_returning("Sorry, this shop is currently unavailable"))
    assert result.status == "vulnerable"
    assert result.service == "Shopify"


def test_fastly_unknown_domain_is_vulnerable():
    resolver = FakeResolver({"cdn.example.com": "x.fastly.net"})
    result = check("cdn.example.com", resolver,
                   http_returning("Fastly error: unknown domain"))
    assert result.status == "vulnerable"
    assert result.service == "Fastly"


# --- claimed -------------------------------------------------------------------

def test_github_pages_live_site_is_claimed():
    resolver = FakeResolver({"blog.example.com": "user.github.io"})
    result = check("blog.example.com", resolver,
                   http_returning("<html>Welcome to my blog</html>", 200))
    assert result.status == "claimed"
    assert result.service == "GitHub Pages"


def test_netlify_live_site_is_claimed():
    resolver = FakeResolver({"www.example.com": "site.netlify.app"})
    result = check("www.example.com", resolver,
                   http_returning("<html>real site</html>", 200))
    assert result.status == "claimed"
    assert result.service == "Netlify"


# --- NXDOMAIN handling -----------------------------------------------------------

def test_azure_dangling_cname_is_vulnerable():
    resolver = FakeResolver(
        {"old.example.com": "old.azurewebsites.net"},
        resolving={"old.azurewebsites.net": False})
    result = check("old.example.com", resolver, http_returning("", 0))
    assert result.status == "vulnerable"
    assert result.service == "Microsoft Azure"
    assert "NXDOMAIN" in result.evidence


def test_flyio_dangling_cname_is_vulnerable():
    resolver = FakeResolver(
        {"api.example.com": "api.fly.dev"},
        resolving={"api.fly.dev": False})
    result = check("api.example.com", resolver, http_returning("", 0))
    assert result.status == "vulnerable"
    assert result.service == "Fly.io"


def test_non_nxdomain_service_unresolvable_is_unknown():
    resolver = FakeResolver(
        {"blog.example.com": "user.github.io"},
        resolving={"user.github.io": False})
    result = check("blog.example.com", resolver, http_returning("", 0))
    assert result.status == "unknown"
    assert result.service == "GitHub Pages"


# --- unknown cases -----------------------------------------------------------------

def test_no_cname_is_unknown():
    result = check("plain.example.com", FakeResolver({}),
                   http_returning("anything"))
    assert result.status == "unknown"
    assert result.cname is None
    assert "No CNAME" in result.evidence


def test_unrecognised_cname_target_is_unknown():
    resolver = FakeResolver({"www.example.com": "server1.hosting-provider.net"})
    result = check("www.example.com", resolver, http_returning("ok", 200))
    assert result.status == "unknown"
    assert result.service is None


def test_lookalike_domain_does_not_match_service():
    resolver = FakeResolver({"x.example.com": "user.notgithub.io"})
    result = check("x.example.com", resolver,
                   http_returning("There isn't a GitHub Pages site here."))
    assert result.status == "unknown"


# --- batch + evidence -----------------------------------------------------------------

def test_check_subdomains_batch():
    resolver = FakeResolver({
        "blog.example.com": "user.github.io",
        "plain.example.com": None,
    })
    results = checker.check_subdomains(
        ["blog.example.com", "plain.example.com"], resolver=resolver,
        http_get_fn=http_returning("There isn't a GitHub Pages site here."),
        fingerprints=FPS)
    assert [r.status for r in results] == ["vulnerable", "unknown"]


def test_vulnerable_result_has_remediation_and_evidence():
    resolver = FakeResolver({"blog.example.com": "user.github.io"})
    result = check("blog.example.com", resolver,
                   http_returning("There isn't a GitHub Pages site here."))
    assert "Remove the dangling DNS record" in result.remediation
    assert result.evidence


def test_result_to_dict_shape():
    resolver = FakeResolver({"blog.example.com": "user.github.io"})
    data = check("blog.example.com", resolver,
                 http_returning("hello", 200)).to_dict()
    assert data["subdomain"] == "blog.example.com"
    assert data["status"] == "claimed"
    assert set(data) == {"subdomain", "cname", "service", "status",
                         "evidence", "remediation"}
