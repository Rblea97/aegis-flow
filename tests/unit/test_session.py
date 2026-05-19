from datetime import UTC, datetime

import aegis_remediator.session as session


class FakeStsClient:
    def __init__(self):
        self.assume_role_calls = []

    def assume_role(self, **kwargs):
        self.assume_role_calls.append(kwargs)
        return {
            "Credentials": {
                "AccessKeyId": "access-key",
                "SecretAccessKey": "secret-key",
                "SessionToken": "session-token",
                "Expiration": datetime(2026, 1, 1, tzinfo=UTC),
            }
        }


def test_assume_role_includes_external_id_when_configured(monkeypatch):
    fake_sts = FakeStsClient()
    monkeypatch.setenv("EXECUTION_ROLE_ARN", "arn:aws:iam::123456789012:role/AegisFlow")
    monkeypatch.setenv("EXTERNAL_ID", "aegisflow-release-polish")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setattr(session.boto3, "client", lambda service: fake_sts)

    session.reset_session()

    session._build_assumed_session()

    assert fake_sts.assume_role_calls == [
        {
            "RoleArn": "arn:aws:iam::123456789012:role/AegisFlow",
            "RoleSessionName": "aegisflow-remediator",
            "ExternalId": "aegisflow-release-polish",
        }
    ]


def test_assume_role_omits_external_id_when_unconfigured(monkeypatch):
    fake_sts = FakeStsClient()
    monkeypatch.setenv("EXECUTION_ROLE_ARN", "arn:aws:iam::123456789012:role/AegisFlow")
    monkeypatch.delenv("EXTERNAL_ID", raising=False)
    monkeypatch.setattr(session.boto3, "client", lambda service: fake_sts)

    session.reset_session()

    session._build_assumed_session()

    assert fake_sts.assume_role_calls == [
        {
            "RoleArn": "arn:aws:iam::123456789012:role/AegisFlow",
            "RoleSessionName": "aegisflow-remediator",
        }
    ]
