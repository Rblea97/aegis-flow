import json
import time
from uuid import uuid4
import pytest
from pathlib import Path
from botocore.exceptions import ClientError

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def get_sfn_arn(sfn_client):
    return sfn_client.list_state_machines()["stateMachines"][0]["stateMachineArn"]


def wait_for_complete_item(table, resource_arn: str, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        response = table.get_item(Key={"resource_arn": resource_arn})
        item = response.get("Item")
        if item and item.get("status") == "COMPLETE":
            return item
        time.sleep(0.5)
    pytest.fail(f"Audit record for {resource_arn} did not reach COMPLETE within {timeout}s")


def test_identity_playbook_freezes_principal(iam_client, dynamodb_resource, sfn_client):
    role_name = f"compromised-role-{uuid4().hex[:8]}"
    role_arn = f"arn:aws:iam::123456789012:role/{role_name}"
    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                               "Action": "sts:AssumeRole"}]
            }),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise

    finding = load_fixture("finding_priv_escalation.json")
    finding["detail"]["id"] = f"{role_name}-finding"
    finding["detail"]["resource"]["accessKeyDetails"]["userArn"] = role_arn
    finding["detail"]["resource"]["accessKeyDetails"]["userName"] = role_name
    sfn_client.start_execution(
        stateMachineArn=get_sfn_arn(sfn_client), input=json.dumps(finding)
    )

    table = dynamodb_resource.Table("AegisFlow_ActiveJails")
    item = wait_for_complete_item(table, role_arn)

    policies = iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert "AegisFlow-Deny-All" in policies

    assert item["status"] == "COMPLETE"
    assert item["playbook_type"] == "IDENTITY"
