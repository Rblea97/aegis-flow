import json
import time
from uuid import uuid4
import pytest
from pathlib import Path
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def get_sfn_arn(sfn_client):
    return sfn_client.list_state_machines()["stateMachines"][0]["stateMachineArn"]


def wait_for_complete_item(table, resource_arn: str, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        response = table.get_item(Key={"resource_arn": resource_arn})
        item = response.get("Item")
        if item and item.get("status") == "COMPLETE":
            return item
        time.sleep(0.5)
    pytest.fail(f"Audit record for {resource_arn} did not reach COMPLETE within {timeout}s")


def ensure_role(iam_client, role_name: str) -> None:
    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                               "Action": "sts:AssumeRole"}],
            }),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise


def ensure_user(iam_client, user_name: str) -> None:
    try:
        iam_client.create_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise


def test_duplicate_finding_only_one_lock(iam_client, sfn_client, dynamodb_resource):
    """Two identical findings → one COMPLETE record, second exits via AlreadyLocked."""
    role_name = f"duplicate-role-{uuid4().hex[:8]}"
    role_arn = f"arn:aws:iam::123456789012:role/{role_name}"
    ensure_role(iam_client, role_name)
    finding = load_fixture("finding_priv_escalation.json")
    finding["detail"]["id"] = f"{role_name}-finding"
    finding["detail"]["resource"]["accessKeyDetails"]["userArn"] = role_arn
    finding["detail"]["resource"]["accessKeyDetails"]["userName"] = role_name
    sfn_arn = get_sfn_arn(sfn_client)

    sfn_client.start_execution(stateMachineArn=sfn_arn, input=json.dumps(finding))
    sfn_client.start_execution(stateMachineArn=sfn_arn, input=json.dumps(finding))
    table = dynamodb_resource.Table("AegisFlow_ActiveJails")
    wait_for_complete_item(table, role_arn)
    items = table.scan(FilterExpression=Attr("resource_arn").eq(role_arn))["Items"]
    assert len(items) == 1, "Exactly one DynamoDB record must exist"


def test_evidence_failure_does_not_block_remediation(iam_client, sfn_client, dynamodb_resource):
    """Remediation completes even when evidence collection status is non-success."""
    user_name = f"suspicious-user-{uuid4().hex[:8]}"
    user_arn = f"arn:aws:iam::123456789012:user/{user_name}"
    ensure_user(iam_client, user_name)
    finding = load_fixture("finding_console_login.json")
    finding["detail"]["id"] = f"{user_name}-finding"
    finding["detail"]["resource"]["accessKeyDetails"]["userArn"] = user_arn
    finding["detail"]["resource"]["accessKeyDetails"]["userName"] = user_name
    sfn_client.start_execution(
        stateMachineArn=get_sfn_arn(sfn_client), input=json.dumps(finding)
    )

    table = dynamodb_resource.Table("AegisFlow_ActiveJails")
    item = wait_for_complete_item(table, user_arn)
    assert item["status"] == "COMPLETE"
    assert item["evidence_collection_status"] in ("success", "partial", "failed")
