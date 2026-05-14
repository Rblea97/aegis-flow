import json
import time
import pytest
from pathlib import Path
from boto3.dynamodb.conditions import Attr

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def get_sfn_arn(sfn_client):
    return sfn_client.list_state_machines()["stateMachines"][0]["stateMachineArn"]


def wait_for_execution(sfn, arn, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        resp = sfn.describe_execution(executionArn=arn)
        if resp["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return resp
        time.sleep(0.5)
    pytest.fail("Execution timed out")


def test_duplicate_finding_only_one_lock(sfn_client, dynamodb_resource):
    """Two identical findings → one COMPLETE record, second exits via AlreadyLocked."""
    finding = load_fixture("finding_cryptomining.json")
    sfn_arn = get_sfn_arn(sfn_client)

    exec1 = sfn_client.start_execution(stateMachineArn=sfn_arn, input=json.dumps(finding))
    exec2 = sfn_client.start_execution(stateMachineArn=sfn_arn, input=json.dumps(finding))

    r1 = wait_for_execution(sfn_client, exec1["executionArn"])
    r2 = wait_for_execution(sfn_client, exec2["executionArn"])

    statuses = {r1["status"], r2["status"]}
    assert "SUCCEEDED" in statuses, "At least one execution must succeed"

    finding_detail = finding["detail"]
    account_id = finding_detail["accountId"]
    instance_id = finding_detail["resource"]["instanceDetails"]["instanceId"]
    resource_arn = f"arn:aws:ec2:us-east-1:{account_id}:instance/{instance_id}"

    table = dynamodb_resource.Table("AegisFlow_ActiveJails")
    items = table.scan(FilterExpression=Attr("resource_arn").eq(resource_arn))["Items"]
    assert len(items) == 1, "Exactly one DynamoDB record must exist"


def test_evidence_failure_does_not_block_remediation(sfn_client, dynamodb_resource):
    """Remediation completes even when evidence collection status is non-success."""
    finding = load_fixture("finding_console_login.json")
    exec_resp = sfn_client.start_execution(
        stateMachineArn=get_sfn_arn(sfn_client), input=json.dumps(finding)
    )
    result = wait_for_execution(sfn_client, exec_resp["executionArn"])
    assert result["status"] == "SUCCEEDED"

    resource_arn = finding["detail"]["resource"]["accessKeyDetails"]["userArn"]
    table = dynamodb_resource.Table("AegisFlow_ActiveJails")
    response = table.get_item(Key={"resource_arn": resource_arn})
    assert "Item" in response, f"No DynamoDB record for {resource_arn!r} — execution status: {result['status']}"
    item = response["Item"]
    assert item["status"] == "COMPLETE"
    assert item["evidence_collection_status"] in ("success", "partial", "failed")
