import json
import pytest


# ------------------------------------------------------------------------------
@pytest.mark.smoketest
@pytest.mark.cpesearch
def test_cpe_search_by_id(cli_runner):
    """Search CPEs names by CPE 2.3 specfication and requests output as ID"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cpe --cpe23 cpe:2.3:h:dlink:dir-412:* --output id")
    assert result.returncode == 0
    assert result.stdout[:39] == 'cpe:2.3:h:dlink:dir-412:-:*:*:*:*:*:*:*'


# ------------------------------------------------------------------------------
@pytest.mark.smoketest
@pytest.mark.cpesearch
def test_cpe_search_by_id_json(cli_runner):
    """Search CPE by ID and requests output as JSON"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cpe --cpe23 cpe:2.3:h:dlink:dir-412:* --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert len(data['result']) > 0, "No results returned"
        assert data['result'][0]['cpeName'] == 'cpe:2.3:h:dlink:dir-412:-:*:*:*:*:*:*:*'


# ------------------------------------------------------------------------------
@pytest.mark.cpesearch
def test_cpe_search_by_keyword(cli_runner):
    """Search CPE by regex in the CPE title and requests output as JSON"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cpe --keyword 'D-Link.*Dir-412' --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert len(data['result']) > 0, "No results returned"
        assert 'cpe:2.3:h:dlink:dir-412:-:*:*:*:*:*:*:*' in [cpe['cpeName'] for cpe in data['result']], "Expected CPE name not found"


# ------------------------------------------------------------------------------
@pytest.mark.cpesearch
def test_cpe_search_by_id_check_keys(cli_runner):
    """Search CPE by ID and requests output as JSON. Validate the presense of a list of keys"""

    result = cli_runner.runcommand("docker exec fastcve search --search-info cpe --cpe23 cpe:2.3:h:dlink:dir-412:* --output json")
    assert result.returncode == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        assert False, "JSON output could not be decoded"
    else:
        assert len(data['result']) > 0, "No results returned"
        assert "cpeName" in data['result'][0], "cpeName Key not found in JSON data"
        assert "refs" in data['result'][0], "refs Key not found in JSON data"
        assert "titles" in data['result'][0], "titles Key not found in JSON data"
        assert "created" in data['result'][0], "created Key not found in JSON data"
        assert "cpeNameId" in data['result'][0], "cpeNameId Key not found in JSON data"
        assert "deprecated" in data['result'][0], "deprecated Key not found in JSON data"
        assert "lastModified" in data['result'][0], "lastModified Key not found in JSON data"
