from pytest_mock import mocker
from commitguard import githubclient
import pytest
import requests
import os

from commitguard.githubclient import GitHubClient




def test_auth_github_api(mocker, caplog):
    mocker.patch("commitguard.githubclient.os.getenv", return_value="token")

    fake = mocker.Mock()
    fake.status_code = 200
    fake.json.return_value = {"login": "tester"}
    fake.headers = {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "59"}

    mocker.patch("commitguard.githubclient.requests.Session.get", return_value=fake)

    ghc = GitHubClient("")

    with caplog.at_level("INFO"):
        ghc.authorize_github_api()

    assert "Auth in Github API successful" in caplog.text


# #region FETCHING COMMITS
# def test_github_fetching_sync(mocker, caplog):
#
#     mocker.patch("commitguard.githubclient.os.getenv", return_value="token")
#
#     fake_user = mocker.Mock(status_code=200)
#     fake_user.json.return_value = {"login": "octocat"}
#     fake_user.headers = {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "59"}
#
#     fake_commits = mocker.Mock(status_code=200)
#     fake_commits.json.return_value = [
#         {"sha": "abc123", "commit": {"message": "Init commit"}},
#         {"sha": "def456", "commit": {"message": ""}},
#     ]
#     fake_commits.headers = {}
#
#     ####################################################
#     fake_detail_abc = mocker.Mock(status_code=200)
#     fake_detail_def = mocker.Mock(status_code=200)
#
#     fake_detail_abc.json.return_value = {
#         "sha": "abc123", "commit": {"message": "Init commit"}, "files": [],
#     }
#
#     fake_detail_def.json.return_value = {
#         "sha": "def456", "commit": {"message": ""}, "files": [],
#     }
#
#     def get_side_effect(url, *a, **k):
#         if url.endswith("/user"): return fake_user
#         if url.endswith("/commits"): return fake_commits
#         if url.endswith("/commits/abc123"): return fake_detail_abc
#         if url.endswith("/commits/def456"): return fake_detail_def
#         raise AssertionError(f"Unexpected URL: {url}")
#
#     mocker.patch("commitguard.githubclient.requests.Session.get", side_effect=get_side_effect)
#
#     ghc = GitHubClient("")
#
#     with caplog.at_level("INFO"):
#         ghc.authorize_github_api()
#         ghc.run_fetching_sync(2)
#
#     assert "Auth in Github API successful" in caplog.text
#     assert "Fetching commit(s)" in caplog.text
#     assert "Successfully fetched" in caplog.text
#
# @pytest.mark.asyncio
# async def test_auth_then_fetching_async_logs_only(mocker, caplog):
#     mocker.patch("commitguard.githubclient.os.getenv", return_value="dummy_token")
#
#     fake_user = mocker.Mock(status_code=200)
#     fake_user.json.return_value = {"login": "octocat"}
#     fake_user.headers = {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "59"}
#
#     fake_commits = mocker.Mock(status_code=200)
#     fake_commits.json.return_value = [
#         {"sha": "abc123", "commit": {"message": "Init commit"}},
#         {"sha": "def456", "commit": {"message": ""}},
#     ]
#     fake_commits.headers = {}
#
#     fake_detail_abc = mocker.Mock(status_code=200)
#     fake_detail_abc.json.return_value = {
#         "sha": "abc123", "commit": {"message": "Init commit"}, "files": [],
#     }
#
#     fake_detail_def = mocker.Mock(status_code=200)
#     fake_detail_def.json.return_value = {
#         "sha": "def456", "commit": {"message": ""}, "files": [],
#     }
#
#     def get_side_effect(url, *args, **kwargs):
#         if url.endswith("/user"):
#             return fake_user
#         if url.endswith("/commits/abc123"):
#             return fake_detail_abc
#         if url.endswith("/commits/def456"):
#             return fake_detail_def
#         if url.endswith("/commits"):
#             return fake_commits
#         raise AssertionError(f"Unexpected URL: {url}")
#
#     mocker.patch("commitguard.githubclient.requests.Session.get", side_effect=get_side_effect)
#
#     ghc = GitHubClient("https://github.com/owner/repo.git")
#
#     with caplog.at_level("INFO"):
#         ghc.authorize_github_api()
#         await ghc.run_fetching_async(2,10)
#
#     assert "Auth in Github API successful" in caplog.text
#     assert "Fetching commit(s)" in caplog.text
#     assert "Successfully fetched" in caplog.text
# #endregion
#
#region UNSUCCESSFUL AUTHORIZATION
def test_authorize_no_token(mocker, caplog):

    mocker.patch("commitguard.githubclient.os.getenv", return_value=None)
    ghc = GitHubClient("")

    with caplog.at_level("ERROR"):
        with pytest.raises(SystemExit) as e:
            ghc.authorize_github_api()

    assert e.value.code == 1
    assert "Error there is no GITHUB_TOKEN in environment" in caplog.text

@pytest.mark.parametrize("status,msg", [
    (201, "Created"),
    (204, "No Content"),
    (301, "Moved Permanently"),
    (400, "Bad Request"),
    (403, "Forbidden"),
    (404, "Not Found"),
    (500, "Internal Server Error"),
])
def test_api_errors(mocker, caplog, status, msg):
    mocker.patch("commitguard.githubclient.os.getenv", return_value="token")

    fake = mocker.Mock(status_code=status)
    fake.raise_for_status.side_effect = requests.HTTPError(f"{status} {msg}")
    mocker.patch("commitguard.githubclient.requests.Session.get", return_value=fake)

    ghc = GitHubClient("")

    with caplog.at_level("ERROR"):
        with pytest.raises(SystemExit) as e:
            ghc.authorize_github_api()

    assert e.value.code == 1
    assert str(status) in caplog.text
#endregion


def test_auth_api_json_error(mocker, caplog):
    mocker.patch("commitguard.githubclient.os.getenv", return_value="token")

    fake = mocker.Mock()
    fake.status_code = 200
    fake.text = "some text"
    fake.headers = {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "59"}
    fake.json.side_effect = ValueError("No JSON object could be decoded")

    mocker.patch("commitguard.githubclient.requests.Session.get", return_value=fake)

    ghc = GitHubClient("")

    with caplog.at_level("ERROR"):
        with pytest.raises(SystemExit) as e:
            ghc.authorize_github_api()

    assert e.value.code == 1
    assert "Auth failed: response is not valid JSON" in caplog.text




