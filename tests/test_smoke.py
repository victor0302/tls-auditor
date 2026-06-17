from tls_auditor import __version__
from tls_auditor.cli import build_parser, main


def test_version():
    assert __version__ == "0.1.0"


def test_parser_accepts_target():
    args = build_parser().parse_args(["example.com:443"])
    assert args.target == "example.com:443"


def test_main_returns_zero(capsys):
    rc = main(["example.com:443"])
    assert rc == 0
    assert "tls-auditor" in capsys.readouterr().out
