from click.testing import CliRunner
from driftmux.cli import main


def test_cli_requires_host_or_host_file():
    runner = CliRunner()
    result = runner.invoke(main, [])
    assert result.exit_code != 0
    assert "Provide --host or --host-file" in result.output
