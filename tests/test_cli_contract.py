from click.testing import CliRunner
from driftmux.cli import main


def test_cli_requires_scan_input():
    runner = CliRunner()
    result = runner.invoke(main, [])

    assert result.exit_code != 0
    assert "Provide one of --host, --host-file or --target" in result.output