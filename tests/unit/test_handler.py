import os

import pytest

os.environ.setdefault("ACTIVE_JAILS_TABLE", "AegisFlow_ActiveJails")
os.environ.setdefault("FORENSICS_BUCKET", "aegisflow-forensics-test")
os.environ.setdefault("QUARANTINE_SG_ID", "sg-quarantine")
os.environ.setdefault("SNS_ALERT_TOPIC_ARN", "")
os.environ.setdefault("EXECUTION_ROLE_ARN", "arn:aws:iam::123456789012:role/AegisFlow-Remediation-Execution-Role")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

def test_handler_rejects_unknown_action():
    from aegis_remediator.handler import handler
    with pytest.raises(ValueError, match="Unknown action"):
        handler({"action": "DoNothing", "context": {}}, None)

def test_handler_validate_event_returns_context():
    from aegis_remediator.handler import handler
    event = {
        "action": "ValidateEvent",
        "context": {
            "source": "aws.guardduty",
            "detail-type": "GuardDuty Finding",
            "detail": {
                "id": "f1", "type": "Impact:EC2/CryptoMining",
                "severity": 8.0, "region": "us-east-1", "accountId": "123456789012",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "instanceId": "i-abc",
                        "networkInterfaces": [{"networkInterfaceId": "eni-abc"}],
                    },
                },
            },
        },
    }
    result = handler(event, None)
    assert result["playbook_type"] == "COMPUTE"
    assert result["instance_id"] == "i-abc"
