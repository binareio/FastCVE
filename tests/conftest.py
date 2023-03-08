import pytest
import os

from tests.runners.cli_runner import CLIRunner


def pytest_configure(config):
    config.addinivalue_line("markers", "smoketest: marker for smoke tests")
    config.addinivalue_line("markers", "cwesearch: marker for testing the CWE search only")
    config.addinivalue_line("markers", "cvesearch: marker for testing the CVE search only")
    config.addinivalue_line("markers", "cpesearch: marker for testing the CPE search only")


@pytest.fixture(scope="session")
def cli_runner():
    """Set up the CLI runner that would be used to trigger the tests.

    Yields:
        CLIRunner: The CLI runner.
    """

    os.environ["INP_ENV_NAME"] = "dev"
    os.environ["FCDB_HOME"] = os.getcwd()

    # make sure the docker with DB image is up and running
    runner = CLIRunner()
    print("triggering: docker compose up -d")
    result = runner.runcommand("docker compose up -d")
    assert result.returncode == 0
    yield runner

    print("triggering: docker compose down")
    runner.runcommand("docker compose down")

