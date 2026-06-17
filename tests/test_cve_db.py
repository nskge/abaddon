"""Tests for the CVE database matching and version extraction logic."""

import pytest
from scanner.cve_db import (
    _ver, _lt, _eq, _between,
    match_cves, extract_versions, _CVE_DB,
)


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

class TestVerParsing:
    def test_simple_version(self):
        assert _ver("2.4.49") == (2, 4, 49)

    def test_two_part(self):
        assert _ver("6.0") == (6, 0)

    def test_single(self):
        assert _ver("10") == (10,)

    def test_trailing_letter(self):
        # Letters break the chain -- only numeric parts kept
        assert _ver("1.0.1f") == (1, 0, 1)

    def test_complex_suffix(self):
        # Dash is a separator; "3" from "-3ubuntu1" is included
        assert _ver("2.4.49-3ubuntu1") == (2, 4, 49, 3)

    def test_empty(self):
        assert _ver("") == (0,)

    def test_major_only(self):
        assert _ver("9") == (9,)

    def test_four_part(self):
        assert _ver("12.2.1.4.0") == (12, 2, 1, 4, 0)


class TestVersionComparison:
    def test_lt_true(self):
        assert _lt("2.4.49", "2.4.52") is True

    def test_lt_false(self):
        assert _lt("2.4.52", "2.4.28") is False

    def test_lt_equal(self):
        assert _lt("2.4.49", "2.4.49") is False

    def test_eq_true(self):
        assert _eq("2.4.49", "2.4.49") is True

    def test_eq_false(self):
        assert _eq("2.4.50", "2.4.49") is False

    def test_between_inclusive_low(self):
        assert _between("2.4.49", "2.4.49", "2.4.50") is True

    def test_between_inclusive_high(self):
        assert _between("2.4.50", "2.4.49", "2.4.50") is True

    def test_between_inside(self):
        assert _between("1.18.0", "0.6.18", "1.20.0") is True

    def test_between_outside(self):
        assert _between("1.21.0", "0.6.18", "1.20.0") is False

    def test_between_below(self):
        assert _between("0.5.0", "0.6.18", "1.20.0") is False


# ---------------------------------------------------------------------------
# CVE matching -- original 18 entries
# ---------------------------------------------------------------------------

class TestCVEMatchingOriginal:
    def test_apache_2_4_49_rce(self):
        matches = match_cves([("apache", "2.4.49")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2021-41773" in cve_ids
        assert "CVE-2021-42013" in cve_ids

    def test_apache_2_4_49_also_matches_range_cves(self):
        matches = match_cves([("apache", "2.4.49")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2021-44790" in cve_ids
        assert "CVE-2023-25690" in cve_ids

    def test_apache_modern_no_match(self):
        assert len(match_cves([("apache", "2.4.62")])) == 0

    def test_nginx_old_matches(self):
        cve_ids = {m["cve"] for m in match_cves([("nginx", "1.12.0")])}
        assert "CVE-2021-23017" in cve_ids
        assert "CVE-2017-7529" in cve_ids

    def test_nginx_modern_no_match(self):
        assert len(match_cves([("nginx", "1.25.0")])) == 0

    def test_php_7_2_matches_fpm(self):
        cve_ids = {m["cve"] for m in match_cves([("php", "7.2.10")])}
        assert "CVE-2019-11043" in cve_ids

    def test_php_8_1_old_matches_cgi(self):
        cve_ids = {m["cve"] for m in match_cves([("php", "8.1.15")])}
        assert "CVE-2024-4577" in cve_ids

    def test_iis_6_matches(self):
        cve_ids = {m["cve"] for m in match_cves([("iis", "6.0")])}
        assert "CVE-2017-7269" in cve_ids

    def test_iis_10_no_match(self):
        assert len(match_cves([("iis", "10.0")])) == 0

    def test_tomcat_ghostcat(self):
        cve_ids = {m["cve"] for m in match_cves([("tomcat", "9.0.20")])}
        assert "CVE-2020-1938" in cve_ids

    def test_tomcat_modern_no_match(self):
        assert len(match_cves([("tomcat", "10.1.5")])) == 0

    def test_jquery_old_matches(self):
        cve_ids = {m["cve"] for m in match_cves([("jquery", "3.4.1")])}
        assert "CVE-2020-11022" in cve_ids

    def test_jquery_modern_no_match(self):
        assert len(match_cves([("jquery", "3.7.0")])) == 0

    def test_openssl_heartbleed(self):
        cve_ids = {m["cve"] for m in match_cves([("openssl", "1.0.1e")])}
        assert "CVE-2014-0160" in cve_ids

    def test_openssl_fixed_no_heartbleed(self):
        # 1.0.1g is the patch
        cve_ids = {m["cve"] for m in match_cves([("openssl", "1.0.1g")])}
        assert "CVE-2014-0160" not in cve_ids

    def test_wordpress_old_sqli(self):
        cve_ids = {m["cve"] for m in match_cves([("wordpress", "5.7.0")])}
        assert "CVE-2022-21661" in cve_ids


# ---------------------------------------------------------------------------
# CVE matching -- new entries (17 additional)
# ---------------------------------------------------------------------------

class TestCVEMatchingNew:
    # -- Nginx --
    def test_nginx_request_smuggling(self):
        cve_ids = {m["cve"] for m in match_cves([("nginx", "1.16.0")])}
        assert "CVE-2019-20372" in cve_ids

    def test_nginx_smuggling_fixed(self):
        cve_ids = {m["cve"] for m in match_cves([("nginx", "1.17.7")])}
        assert "CVE-2019-20372" not in cve_ids

    # -- PHP --
    def test_php_phar_overflow(self):
        cve_ids = {m["cve"] for m in match_cves([("php", "8.1.15")])}
        assert "CVE-2023-3824" in cve_ids

    def test_php_phar_fixed(self):
        cve_ids = {m["cve"] for m in match_cves([("php", "8.1.22")])}
        assert "CVE-2023-3824" not in cve_ids

    # -- Tomcat --
    def test_tomcat_cgi_windows_rce(self):
        cve_ids = {m["cve"] for m in match_cves([("tomcat", "9.0.10")])}
        assert "CVE-2019-0232" in cve_ids

    def test_tomcat_cgi_fixed(self):
        cve_ids = {m["cve"] for m in match_cves([("tomcat", "9.0.18")])}
        assert "CVE-2019-0232" not in cve_ids

    # -- OpenSSL --
    def test_openssl_bnmodsqrt_loop(self):
        cve_ids = {m["cve"] for m in match_cves([("openssl", "1.1.1k")])}
        assert "CVE-2022-0778" in cve_ids

    def test_openssl_bnmodsqrt_fixed(self):
        cve_ids = {m["cve"] for m in match_cves([("openssl", "1.1.1n")])}
        assert "CVE-2022-0778" not in cve_ids

    # -- WordPress --
    def test_wordpress_path_traversal(self):
        cve_ids = {m["cve"] for m in match_cves([("wordpress", "6.1.0")])}
        assert "CVE-2023-2745" in cve_ids

    def test_wordpress_traversal_fixed(self):
        cve_ids = {m["cve"] for m in match_cves([("wordpress", "6.2.1")])}
        assert "CVE-2023-2745" not in cve_ids

    # -- Drupal --
    def test_drupal_drupalgeddon2(self):
        cve_ids = {m["cve"] for m in match_cves([("drupal", "7.50")])}
        assert "CVE-2018-7600" in cve_ids

    def test_drupal_drupalgeddon2_8x(self):
        cve_ids = {m["cve"] for m in match_cves([("drupal", "8.3.5")])}
        assert "CVE-2018-7600" in cve_ids

    def test_drupal_sa_core_2018_004(self):
        cve_ids = {m["cve"] for m in match_cves([("drupal", "7.55")])}
        assert "CVE-2018-7602" in cve_ids

    def test_drupal_drupalgeddon1(self):
        cve_ids = {m["cve"] for m in match_cves([("drupal", "7.30")])}
        assert "CVE-2014-3704" in cve_ids

    def test_drupal_modern_no_match(self):
        assert len(match_cves([("drupal", "9.5.0")])) == 0

    # -- Struts --
    def test_struts_s2_045(self):
        cve_ids = {m["cve"] for m in match_cves([("struts", "2.3.20")])}
        assert "CVE-2017-5638" in cve_ids

    def test_struts_s2_057(self):
        cve_ids = {m["cve"] for m in match_cves([("struts", "2.5.12")])}
        assert "CVE-2018-11776" in cve_ids

    def test_struts_modern_no_match(self):
        assert len(match_cves([("struts", "2.5.30")])) == 0

    # -- Spring --
    def test_spring4shell(self):
        cve_ids = {m["cve"] for m in match_cves([("spring", "5.3.10")])}
        assert "CVE-2022-22965" in cve_ids

    def test_spring_fixed_no_match(self):
        cve_ids = {m["cve"] for m in match_cves([("spring", "5.3.18")])}
        assert "CVE-2022-22965" not in cve_ids

    # -- WebLogic --
    def test_weblogic_async_deserialization(self):
        cve_ids = {m["cve"] for m in match_cves([("weblogic", "12.1.3")])}
        assert "CVE-2019-2725" in cve_ids

    def test_weblogic_console_bypass(self):
        cve_ids = {m["cve"] for m in match_cves([("weblogic", "12.2.1.3")])}
        assert "CVE-2020-14882" in cve_ids

    def test_weblogic_modern_no_match(self):
        assert len(match_cves([("weblogic", "14.1.2.0")])) == 0

    # -- Confluence --
    def test_confluence_ognl_injection(self):
        cve_ids = {m["cve"] for m in match_cves([("confluence", "7.13.5")])}
        assert "CVE-2022-26134" in cve_ids

    def test_confluence_admin_setup(self):
        cve_ids = {m["cve"] for m in match_cves([("confluence", "8.3.0")])}
        assert "CVE-2023-22515" in cve_ids

    def test_confluence_modern_no_match(self):
        assert len(match_cves([("confluence", "8.6.0")])) == 0

    # -- Joomla --
    def test_joomla_php_object_injection(self):
        cve_ids = {m["cve"] for m in match_cves([("joomla", "3.4.0")])}
        assert "CVE-2015-8562" in cve_ids

    def test_joomla_api_exposure(self):
        cve_ids = {m["cve"] for m in match_cves([("joomla", "4.2.0")])}
        assert "CVE-2023-23752" in cve_ids

    def test_joomla_modern_no_match(self):
        assert len(match_cves([("joomla", "5.0.0")])) == 0


# ---------------------------------------------------------------------------
# Output structure and integrity
# ---------------------------------------------------------------------------

class TestOutputStructure:
    def test_sorted_by_cvss(self):
        matches = match_cves([("apache", "2.4.49")])
        scores = [m["cvss"] for m in matches]
        assert scores == sorted(scores, reverse=True)

    def test_no_duplicates_same_input(self):
        matches = match_cves([("apache", "2.4.49"), ("apache", "2.4.49")])
        cve_ids = [m["cve"] for m in matches]
        assert len(cve_ids) == len(set(cve_ids))

    def test_multiple_services(self):
        matches = match_cves([("apache", "2.4.49"), ("php", "7.2.10")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2021-41773" in cve_ids
        assert "CVE-2019-11043" in cve_ids

    def test_unknown_service_ignored(self):
        assert len(match_cves([("unknownxyz", "1.0.0")])) == 0

    def test_empty_version_ignored(self):
        assert len(match_cves([("apache", "")])) == 0

    def test_advisory_url_present(self):
        matches = match_cves([("apache", "2.4.49")])
        for m in matches:
            assert "advisory" in m
            assert m["advisory"].startswith("https://nvd.nist.gov/vuln/detail/CVE-")

    def test_msf_payload_field_present(self):
        matches = match_cves([("apache", "2.4.49")])
        for m in matches:
            assert "msf_payload" in m

    def test_msf_entries_have_correct_prefix(self):
        matches = match_cves([("apache", "2.4.49")])
        for m in matches:
            if m["msf"]:
                assert m["msf"].startswith(("exploit/", "auxiliary/"))

    def test_all_entries_have_required_fields(self):
        """Every entry in _CVE_DB must have the required fields."""
        required = {"service", "check", "cve", "cvss", "severity", "impact", "msf"}
        for i, entry in enumerate(_CVE_DB):
            missing = required - set(entry.keys())
            assert not missing, f"Entry {i} ({entry.get('cve', '?')}) missing: {missing}"

    def test_cvss_scores_in_valid_range(self):
        for entry in _CVE_DB:
            assert 0.0 <= entry["cvss"] <= 10.0, (
                f"{entry['cve']} has invalid CVSS {entry['cvss']}"
            )

    def test_severity_values_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for entry in _CVE_DB:
            assert entry["severity"] in valid, (
                f"{entry['cve']} has invalid severity {entry['severity']!r}"
            )

    def test_database_size(self):
        """DB should have at least 34 entries."""
        assert len(_CVE_DB) >= 34

    def test_cve_ids_unique(self):
        """All CVE IDs in the DB should be unique."""
        cve_ids = [e["cve"] for e in _CVE_DB]
        assert len(cve_ids) == len(set(cve_ids)), "Duplicate CVE IDs in _CVE_DB"


# ---------------------------------------------------------------------------
# Version extraction from mock responses
# ---------------------------------------------------------------------------

class FakeResp:
    def __init__(self, headers=None, body=""):
        self.headers = headers or {}
        self.text = body


class TestVersionExtraction:
    def test_apache_from_server_header(self):
        resp = FakeResp({"Server": "Apache/2.4.49 (Ubuntu)"})
        versions = extract_versions(resp)
        assert ("apache", "2.4.49") in versions

    def test_php_from_powered_by(self):
        resp = FakeResp({"X-Powered-By": "PHP/7.2.10"})
        versions = extract_versions(resp)
        assert ("php", "7.2.10") in versions

    def test_openssl_from_server(self):
        resp = FakeResp({"Server": "Apache/2.4.49 OpenSSL/1.0.1e"})
        versions = extract_versions(resp)
        assert ("openssl", "1.0.1e") in versions

    def test_tomcat_from_server(self):
        resp = FakeResp({"Server": "Apache Tomcat/9.0.20"})
        versions = extract_versions(resp)
        assert ("tomcat", "9.0.20") in versions

    def test_iis_from_server(self):
        resp = FakeResp({"Server": "Microsoft-IIS/6.0"})
        versions = extract_versions(resp)
        assert ("iis", "6.0") in versions

    def test_weblogic_from_server(self):
        # Use 4-part version string (no trailing build number)
        resp = FakeResp({"Server": "WebLogic 12.2.1.3"})
        versions = extract_versions(resp)
        assert ("weblogic", "12.2.1.3") in versions

    def test_wordpress_from_body(self):
        body = '<meta name="generator" content="WordPress 5.7.0">'
        resp = FakeResp(body=body)
        versions = extract_versions(resp)
        assert ("wordpress", "5.7.0") in versions

    def test_jquery_from_body(self):
        body = '<script src="/js/jquery-3.4.1.min.js"></script>'
        resp = FakeResp(body=body)
        versions = extract_versions(resp)
        assert ("jquery", "3.4.1") in versions

    def test_joomla_from_body(self):
        body = '<meta name="generator" content="Joomla! 4.2.0 - Open Source Content Management">'
        resp = FakeResp(body=body)
        versions = extract_versions(resp)
        assert ("joomla", "4.2.0") in versions

    def test_drupal_from_body(self):
        body = '<meta name="generator" content="Drupal 8.3.5 (https://www.drupal.org)">'
        resp = FakeResp(body=body)
        versions = extract_versions(resp)
        assert ("drupal", "8.3.5") in versions

    def test_no_duplicates_from_same_header(self):
        resp = FakeResp({"Server": "Apache/2.4.49 Apache/2.4.49"})
        versions = extract_versions(resp)
        apache_entries = [v for v in versions if v[0] == "apache"]
        assert len(apache_entries) == 1

    def test_empty_response_no_versions(self):
        resp = FakeResp()
        assert extract_versions(resp) == []

    # ---- New fingerprints: Jenkins / GitLab / Grafana ----

    def test_jenkins_from_x_jenkins_header(self):
        resp = FakeResp({"X-Jenkins": "2.426.1"})
        versions = extract_versions(resp)
        assert ("jenkins", "2.426.1") in versions

    def test_gitlab_from_body(self):
        body = 'GitLab Community Edition v13.10.0 footer'
        resp = FakeResp(body=body)
        versions = extract_versions(resp)
        assert any(svc == "gitlab" for svc, _ in versions)

    def test_grafana_from_body(self):
        body = '<title>Grafana v8.2.0</title>'
        resp = FakeResp(body=body)
        versions = extract_versions(resp)
        assert ("grafana", "8.2.0") in versions


class TestNewServiceCVEs:
    def test_jenkins_file_read_cve(self):
        matches = match_cves([("jenkins", "2.426.1")])
        assert any(m["cve"] == "CVE-2024-23897" for m in matches)

    def test_gitlab_exiftool_rce(self):
        matches = match_cves([("gitlab", "13.9.0")])
        assert any(m["cve"] == "CVE-2021-22205" for m in matches)

    def test_grafana_path_traversal(self):
        matches = match_cves([("grafana", "8.2.0")])
        assert any(m["cve"] == "CVE-2021-43798" for m in matches)

    def test_patched_jenkins_no_match(self):
        matches = match_cves([("jenkins", "2.500")])
        assert not any(m["cve"] == "CVE-2024-23897" for m in matches)
