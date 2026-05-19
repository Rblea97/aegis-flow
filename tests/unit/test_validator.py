import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures"

def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())

def test_validate_cryptomining_returns_compute_context():
    from aegis_remediator.validator import validate_event
    event = load_fixture("finding_cryptomining.json")
    ctx = validate_event(event)
    assert ctx.playbook_type == "COMPUTE"
    assert ctx.instance_id == "i-0123456789abcdef0"
    assert "arn:aws:ec2:" in ctx.resource_arn

def test_validate_console_login_returns_identity_context():
    from aegis_remediator.validator import validate_event
    event = load_fixture("finding_console_login.json")
    ctx = validate_event(event)
    assert ctx.playbook_type == "IDENTITY"
    assert ctx.principal_arn.startswith("arn:aws:iam:")
    assert ctx.principal_arn == "arn:aws:iam::123456789012:user/suspicious-user"
    assert ctx.resource_arn == ctx.principal_arn

def test_validate_rejects_invalid_arn():
    from aegis_remediator.validator import validate_event
    event = load_fixture("finding_console_login.json")
    event["detail"]["resource"]["accessKeyDetails"]["userArn"] = "../../etc/passwd"
    with pytest.raises(ValueError, match="ARN failed validation"):
        validate_event(event)

def test_validate_rejects_unknown_finding_type():
    from aegis_remediator.validator import validate_event
    event = load_fixture("finding_cryptomining.json")
    event["detail"]["type"] = "Recon:EC2/PortProbeUnprotectedPort"
    with pytest.raises(ValueError, match="Unsupported finding type"):
        validate_event(event)
