"""Tests for the interactive Abaddon menu (logic, not keyboard I/O)."""

import io
import unittest
from unittest import mock

from rich.console import Console

from abaddon import menu
from abaddon.menu import (
    ABADDON_ART,
    MAIN_MENU,
    SCAN_MODULES,
    MenuState,
    _in_scope,
    make_console,
    render_banner,
    render_menu,
)


class TestMenuData(unittest.TestCase):

    def test_art_is_multiline_braille(self):
        lines = ABADDON_ART.split("\n")
        self.assertGreater(len(lines), 20)
        # Braille block chars present
        self.assertTrue(any("⣿" in ln for ln in lines))

    def test_every_main_menu_key_has_handler_or_is_terminal(self):
        for key, _, _ in MAIN_MENU:
            if key == "0":
                continue
            self.assertIn(key, menu._DISPATCH, f"no handler for menu key {key}")

    def test_dispatch_has_no_orphans(self):
        valid_keys = {k for k, _, _ in MAIN_MENU}
        for key in menu._DISPATCH:
            self.assertIn(key, valid_keys)

    def test_scan_modules_cover_core_classes(self):
        keys = {k for k, _ in SCAN_MODULES}
        for expected in ("sqli", "xss", "lfi", "idor", "ssrf", "graphql"):
            self.assertIn(expected, keys)


class TestMenuState(unittest.TestCase):

    def test_build_config_has_required_keys(self):
        state = MenuState()
        config = state.build_config("http://t.local/?id=1", "sqli")
        required = {
            "url", "method", "data", "param", "scan_type", "crawl", "js_crawl",
            "custom_payloads", "delay_threshold", "headers", "cookies", "proxy",
            "timeout", "follow_redirects", "threads", "verbose", "quiet",
            "no_color", "waf_evasion", "port_scan", "discover_paths",
            "discover_subs", "rate_limit", "rate_limit_delay", "orchestrated",
        }
        self.assertTrue(required.issubset(config.keys()))
        self.assertEqual(config["scan_type"], "sqli")
        self.assertEqual(config["url"], "http://t.local/?id=1")

    def test_overrides_applied(self):
        state = MenuState()
        config = state.build_config("http://t/", "headers", port_scan=True, discover_subs=True)
        self.assertTrue(config["port_scan"])
        self.assertTrue(config["discover_subs"])

    def test_proxy_empty_becomes_none(self):
        state = MenuState(proxy="")
        self.assertIsNone(state.build_config("http://t/", "all")["proxy"])

    def test_state_values_flow_into_config(self):
        state = MenuState(threads=16, timeout=20, waf_evasion=2, method="POST")
        config = state.build_config("http://t/", "xss")
        self.assertEqual(config["threads"], 16)
        self.assertEqual(config["timeout"], 20)
        self.assertEqual(config["waf_evasion"], 2)
        self.assertEqual(config["method"], "POST")

    def test_summary_is_string(self):
        self.assertIn("threads=", MenuState().summary())

    def test_cookies_raw_parsed_into_dict(self):
        state = MenuState(cookies_raw="session=abc123; role=admin")
        config = state.build_config("http://t/", "all")
        self.assertEqual(config["cookies"]["session"], "abc123")
        self.assertEqual(config["cookies"]["role"], "admin")

    def test_cookies_empty_gives_empty_dict(self):
        state = MenuState(cookies_raw="")
        config = state.build_config("http://t/", "all")
        self.assertEqual(config["cookies"], {})

    def test_summary_shows_cookie_key(self):
        state = MenuState(cookies_raw="session=abc")
        self.assertIn("cookies=session=...", state.summary())

    def test_ext_tools_in_config(self):
        state = MenuState(use_sqlmap=True, use_nuclei=True, use_wpscan=True)
        config = state.build_config("http://t/", "all")
        self.assertTrue(config["use_sqlmap"])
        self.assertTrue(config["use_nuclei"])
        self.assertTrue(config["use_wpscan"])


class TestScope(unittest.TestCase):

    def test_empty_scope_allows_all(self):
        self.assertTrue(_in_scope("http://anything/", ""))

    def test_glob_match(self):
        self.assertTrue(_in_scope("http://api.example.com/", "*.example.com"))
        self.assertFalse(_in_scope("http://evil.com/", "*.example.com"))

    def test_multi_pattern(self):
        self.assertTrue(_in_scope("http://b.test/", "*.example.com, *.test"))


class TestRendering(unittest.TestCase):

    def _console(self):
        return Console(theme=menu.ABADDON_THEME, file=io.StringIO(), force_terminal=True, width=100)

    def test_render_banner_no_crash(self):
        c = self._console()
        render_banner(c)
        out = c.file.getvalue()
        self.assertIn("A B A D D O N", out)

    def test_render_menu_no_crash(self):
        c = self._console()
        render_menu(c, MAIN_MENU, MenuState())
        out = c.file.getvalue()
        self.assertIn("Quick Scan", out)

    def test_make_console_returns_console(self):
        self.assertIsInstance(make_console(), Console)


class TestRunMenuExit(unittest.TestCase):

    def test_run_menu_exits_on_zero(self):
        c = Console(theme=menu.ABADDON_THEME, file=io.StringIO(), force_terminal=True, width=100)
        with mock.patch("rich.prompt.Prompt.ask", return_value="0"):
            rc = menu.run_menu(state=MenuState(), console=c)
        self.assertEqual(rc, 0)

    def test_run_menu_handles_quick_scan_then_exit(self):
        c = Console(theme=menu.ABADDON_THEME, file=io.StringIO(), force_terminal=True, width=100)
        # First selection: "1" (quick scan), then "0" to exit.
        with mock.patch("rich.prompt.Prompt.ask", side_effect=["1", "0"]), \
             mock.patch.object(menu, "_ask_url", return_value=None), \
             mock.patch.object(c, "input", return_value=""):
            rc = menu.run_menu(state=MenuState(), console=c)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
