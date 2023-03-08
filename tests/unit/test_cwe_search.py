import json
import pytest


# ------------------------------------------------------------------------------
@pytest.mark.smoketest
@pytest.mark.cwesearch
def test_cwe_search_by_id(cli_runner):
    """Search CWE by ID and requests output as ID"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cwe --cwe CWE-79 --output id")
    assert result.returncode == 0
    assert result.stdout[:2] == '79'


# ------------------------------------------------------------------------------
@pytest.mark.smoketest
@pytest.mark.cwesearch
def test_cwe_search_by_id_json(cli_runner):
    """Search CWE by ID and requests output as JSON"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cwe --cwe 79 --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert data['result'][0]['ID'] == '79'


# ------------------------------------------------------------------------------
@pytest.mark.cwesearch
def test_cwe_search_by_keyword(cli_runner):
    """Search CWE by regex and requests output as JSON"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cwe --keyword 'does not neutralize.*page.*served.*users' --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert data['result'][0]['ID'] == '79'


# ------------------------------------------------------------------------------
@pytest.mark.cwesearch
def test_cwe_search_by_id_check_keys(cli_runner):
    """Search CWE by ID and requests output as JSON. Validate the presense of a list of keys"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cwe --cwe 79 --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert "ID" in data['result'][0], "ID Key not found in JSON data"
        assert "Name" in data['result'][0], "Name Key not found in JSON data"
        assert "Status" in data['result'][0], "Status Key not found in JSON data"
        assert "Description" in data['result'][0], "Description Key not found in JSON data"
        assert "Related_Weaknesses" in data['result'][0], "Related_Weaknesses Key not found in JSON data"
        assert "Related_Attack_Patterns" in data['result'][0], "Related_Attack_Patterns Key not found in JSON data"
        assert "Taxonomy_Mappings" in data['result'][0], "Taxonomy_Mappings Key not found in JSON data"
        assert "Potential_Mitigations" in data['result'][0], "Potential_Mitigations Key not found in JSON data"
        assert "Applicable_Platforms" in data['result'][0], "Applicable_Platforms Key not found in JSON data"


@pytest.mark.cwesearch
def test_cwe_search_by_several_ids_and_split_result(cli_runner):
    """Search CWE by IDs and requests output as JSON. Validate the presense of the search criteria"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cwe --cwe 77 78 79 --output json")

    assert result.returncode == 0

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert 'search' in data, "search Key not found in JSON data"
        assert 'result' in data, "result Key not found in JSON data"
        assert len(data['result']) == 3, "Wrong number of results returned, expected 3"
