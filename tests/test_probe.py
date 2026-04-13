from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import probe


def test_normalize_url_adds_scheme():
    assert probe.normalize_url("example.com") == "http://example.com"


def test_normalize_url_keeps_scheme():
    assert probe.normalize_url("https://example.com") == "https://example.com"


def test_parse_ports_filters_invalid_values():
    assert probe.parse_ports("22,80,70000,x,443") == [22, 80, 443]


def test_read_wordlist_ignores_comments_and_blanks(tmp_path: Path):
    wordlist = tmp_path / "sample.txt"
    wordlist.write_text("# comment\nadmin\n\n/login/\n", encoding="utf-8")
    assert probe.read_wordlist(wordlist) == ["admin", "login"]
