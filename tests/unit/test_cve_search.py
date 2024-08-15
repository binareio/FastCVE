import json
import pytest


# ------------------------------------------------------------------------------
@pytest.mark.smoketest
@pytest.mark.cvesearch
def test_cve_search_by_id(cli_runner):
    """Search CVEs by ID and requests output as ID"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cve --cve CVE-1999-0001 --output id")
    assert result.returncode == 0
    assert result.stdout[:13] == 'CVE-1999-0001'


# ------------------------------------------------------------------------------
@pytest.mark.smoketest
@pytest.mark.cvesearch
def test_cve_search_by_id_json(cli_runner):
    """Search CVE by ID and requests output as JSON"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cve --cve CVE-1999-0001 --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert len(data['result']) > 0, "No results returned"
        assert data['result'][0]['id'] == 'CVE-1999-0001'


# ------------------------------------------------------------------------------
@pytest.mark.cvesearch
def test_cve_search_by_keyword(cli_runner):
    """Search CVE by regex in the summary and requests output as JSON"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cve --keyword 'ip_input.c.*BSD-derived TCP/IP.*crash or hang' --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert len(data['result']) > 0, "No results returned"
        assert data['result'][0]['id'] == 'CVE-1999-0001'


# ------------------------------------------------------------------------------
@pytest.mark.cvesearch
def test_cve_search_by_id_check_keys(cli_runner):
    """Search CVE by ID and requests output as JSON. Validate the presense of a list of keys"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cve --cve CVE-1999-0001 --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert len(data['result']) > 0, "No results returned"
        assert "id" in data['result'][0], "id Key not found in JSON data"
        assert "descriptions" in data['result'][0], "descriptions Key not found in JSON data"
        assert "references" in data['result'][0], "references Key not found in JSON data"
        assert "metrics" in data['result'][0], "metrics Key not found in JSON data"
        assert "published" in data['result'][0], "published Key not found in JSON data"
        assert "lastModified" in data['result'][0], "lastModified Key not found in JSON data"
        assert "weaknesses" in data['result'][0], "weaknesses Key not found in JSON data"
        assert "vulnStatus" in data['result'][0], "vulnStatus Key not found in JSON data"


@pytest.mark.cvesearch
def test_cve_search_by_several_ids(cli_runner):
    """Search CVE by IDs and requests output as JSON. Validate the presense of the search criteria"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cve --cve CVE-1999-0001 CVE-1999-0002 --output json")

    assert result.returncode == 0

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert 'search' in data, "search Key not found in JSON data"
        assert 'result' in data, "result Key not found in JSON data"
        assert len(data['result']) == 2, "Wrong number of results returned, expected 2"

@pytest.mark.cvesearch
def test_cve_search_by_epss_score(cli_runner):
    """Search CVE by epss-score and requests output as JSON. Validate the presense of the search criteria"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cve --epss-score-gt 0.00100 --output json")

    assert result.returncode == 0

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert 'search' in data, "search Key not found in JSON data"
        assert 'result' in data, "result Key not found in JSON data"
