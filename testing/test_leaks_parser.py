import pytest

from commitguard.leaks_parser import LeaksParser


@pytest.mark.parametrize(
    "line, expected_rule, expected_code",
    [
        (
            "DB_PASSWORD=pa$$w0rd12345",
            "UnquotedSecretAssignment",
            "DB_PASSWORD=<REDACTED>",
        ),
        (
            "Authorization: Bearer ya29.synthetic-token",
            "BearerAuthorization",
            "Authorization: Bearer <REDACTED>",
        ),
        (
            "Authorization: Basic dXNlcjpwYXNz",
            "BasicAuthorization",
            "Authorization: Basic <REDACTED>",
        ),
    ],
)
def test_secret_detection_and_redaction(line, expected_rule, expected_code):
    result = LeaksParser().scan_line(line)

    assert result is not None
    assert expected_rule in { match["rule"] for match in result["matches"] }
    assert result["redacted_code"] == expected_code


def test_request_line_is_not_a_secret():
    result = LeaksParser().scan_line("PUT /login HTTP/1.1")

    assert result is None

def test_ci_placeholder_is_recognized():
    result = LeaksParser().scan_line(
        "OPENAI_API_KEY: test-placeholder"
    )

    assert result is not None
    assert result["redacted_code"] == "OPENAI_API_KEY: <REDACTED>"

    match = next(
        item for item in result["matches"]
        if item["rule"] == "UnquotedSecretAssignment"
    )
    assert match["matches_known_placeholder"] is True