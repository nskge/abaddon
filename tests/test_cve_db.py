"""Tests for the CVE database matching logic."""

import pytest
from scanner.cve_db import _ver, _lt, _eq, _between, match_cves


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
        # Letters are dropped by _ver (only numeric parts kept)
        assert _ver("1.0.1f") == (1, 0, 1)

    def test_complex_suffix(self):
        # Dash is a separator, so "3" from "-3ubuntu1" becomes a component
        assert _ver("2.4.49-3ubuntu1") == (2, 4, 49, 3)

    def test_empty(self):
        assert _ver("") == (0,)


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

    def test_between_inclusive(self):
        assert _between("2.4.49", "2.4.49", "2.4.50") is True
        assert _between("2.4.50", "2.4.49", "2.4.50") is True

    def test_between_inside(self):
        assert _between("1.18.0", "0.6.18", "1.20.0") is True

    def test_between_outside(self):
        assert _between("1.21.0", "0.6.18", "1.20.0") is False


# ---------------------------------------------------------------------------
# CVE matching
# ---------------------------------------------------------------------------

class TestCVEMatching:
    def test_apache_2_4_49_matches(self):
        """Apache 2.4.49 should match CVE-2021-41773 and CVE-2021-42013."""
        matches = match_cves([("apache", "2.4.49")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2021-41773" in cve_ids
        assert "CVE-2021-42013" in cve_ids

    def test_apache_2_4_49_also_matches_newer_cves(self):
        """2.4.49 < 2.4.52 so CVE-2021-44790 and CVE-2023-25690 should match too."""
        matches = match_cves([("apache", "2.4.49")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2021-44790" in cve_ids
        assert "CVE-2023-25690" in cve_ids

    def test_apache_latest_no_match(self):
        """A modern Apache should not match any known CVEs."""
        matches = match_cves([("apache", "2.4.62")])
        assert len(matches) == 0

    def test_nginx_old_matches(self):
        matches = match_cves([("nginx", "1.12.0")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2021-23017" in cve_ids
        assert "CVE-2017-7529" in cve_ids

    def test_nginx_modern_no_match(self):
        matches = match_cves([("nginx", "1.25.0")])
        assert len(matches) == 0

    def test_php_7_2_matches_fpm(self):
        matches = match_cves([("php", "7.2.10")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2019-11043" in cve_ids

    def test_php_8_1_old_matches_cgi(self):
        matches = match_cves([("php", "8.1.15")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2024-4577" in cve_ids

    def test_iis_6_matches(self):
        matches = match_cves([("iis", "6.0")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2017-7269" in cve_ids

    def test_iis_10_no_match(self):
        matches = match_cves([("iis", "10.0")])
        assert len(matches) == 0

    def test_tomcat_ghostcat(self):
        matches = match_cves([("tomcat", "9.0.20")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2020-1938" in cve_ids

    def test_tomcat_modern_no_match(self):
        matches = match_cves([("tomcat", "10.1.5")])
        assert len(matches) == 0

    def test_jquery_old_matches(self):
        matches = match_cves([("jquery", "3.4.1")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2020-11022" in cve_ids

    def test_jquery_modern_no_match(self):
        matches = match_cves([("jquery", "3.7.0")])
        assert len(matches) == 0

    def test_sorted_by_cvss(self):
        """Results should be sorted by CVSS descending."""
        matches = match_cves([("apache", "2.4.49")])
        scores = [m["cvss"] for m in matches]
        assert scores == sorted(scores, reverse=True)

    def test_no_duplicates(self):
        """Same service/version submitted twice should not duplicate CVEs."""
        matches = match_cves([("apache", "2.4.49"), ("apache", "2.4.49")])
        cve_ids = [m["cve"] for m in matches]
        assert len(cve_ids) == len(set(cve_ids))

    def test_multiple_services(self):
        """Multiple services in one call should all be matched."""
        matches = match_cves([("apache", "2.4.49"), ("php", "7.2.10")])
        cve_ids = {m["cve"] for m in matches}
        assert "CVE-2021-41773" in cve_ids  # Apache
        assert "CVE-2019-11043" in cve_ids  # PHP

    def test_unknown_service_ignored(self):
        matches = match_cves([("unknownservice", "1.0.0")])
        assert len(matches) == 0

    def test_empty_version_ignored(self):
        matches = match_cves([("apache", "")])
        assert len(matches) == 0

    def test_msf_field_present(self):
        """CVE entries with MSF modules should have them populated."""
        matches = match_cves([("apache", "2.4.49")])
        msf_entries = [m for m in matches if m["msf"]]
        assert len(msf_entries) > 0
        for m in msf_entries:
            assert m["msf"].startswith(("exploit/", "auxiliary/"))
