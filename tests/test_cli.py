from click.testing import CliRunner

from netscanner.cli import cli


def test_plan_command_prints_command_preview():
    result = CliRunner().invoke(
        cli,
        ["plan", "--target", "127.0.0.1", "--ports", "22,80", "--mode", "tcp"],
    )

    assert result.exit_code == 0
    assert "nmap -sT" in result.output
    assert "-p 22,80 127.0.0.1" in result.output


def test_scan_requires_authorization_before_dependencies():
    result = CliRunner().invoke(
        cli,
        ["scan", "--target", "127.0.0.1", "--ports", "22", "--mode", "tcp"],
    )

    assert result.exit_code != 0
    assert "Real scan blocked" in result.output
