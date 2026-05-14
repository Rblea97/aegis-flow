import json
import time
import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def get_sfn_arn(sfn_client):
    return sfn_client.list_state_machines()["stateMachines"][0]["stateMachineArn"]


def wait_for_execution(sfn, arn, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        resp = sfn.describe_execution(executionArn=arn)
        if resp["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return resp
        time.sleep(0.5)
    pytest.fail("Execution timed out")


def test_identity_playbook_freezes_principal(iam_client, dynamodb_resource, sfn_client):
    iam_client.create_role(
        RoleName="compromised-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]
        }),
    )

    finding = load_fixture("finding_priv_escalation.json")
    exec_resp = sfn_client.start_execution(
        stateMachineArn=get_sfn_arn(sfn_client), input=json.dumps(finding)
    )
    result = wait_for_execution(sfn_client, exec_resp["executionArn"])
    assert result["status"] == "SUCCEEDED"

    policies = iam_client.list_role_policies(RoleName="compromised-role")["PolicyNames"]
    assert "AegisFlow-Deny-All" in policies

    resource_arn = finding["detail"]["resource"]["accessKeyDetails"]["userArn"]
    table = dynamodb_resource.Table("AegisFlow_ActiveJails")
    response = table.get_item(Key={"resource_arn": resource_arn})
    assert "Item" in response, f"No DynamoDB record for {resource_arn!r} — execution status: {result['status']}"
    item = response["Item"]
    assert item["status"] == "COMPLETE"
    assert item["playbook_type"] == "IDENTITY"
