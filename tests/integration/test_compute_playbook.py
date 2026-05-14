import json
import time
import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"
ENDPOINT = "http://localhost:4566"
CREDS = {"aws_access_key_id": "test", "aws_secret_access_key": "test",
          "region_name": "us-east-1", "endpoint_url": ENDPOINT}


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def wait_for_execution(sfn, execution_arn: str, timeout: int = 10) -> dict:
    start = time.time()
    while time.time() - start < timeout:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return resp
        time.sleep(0.5)
    pytest.fail(f"Execution did not complete within {timeout}s")


@pytest.fixture
def test_instance(ec2_client):
    """Pre-provisioned EC2 instance with WebTier-SG."""
    env = dict(
        line.strip().split("=", 1)
        for line in Path("/tmp/aegisflow-env").read_text().splitlines()
        if "=" in line
    )
    instance = ec2_client.run_instances(
        ImageId="ami-00000000", MinCount=1, MaxCount=1,
        SecurityGroupIds=[env["WEB_SG_ID"]], SubnetId=env["SUBNET_ID"],
    )["Instances"][0]
    yield {"instance_id": instance["InstanceId"],
           "eni_id": instance["NetworkInterfaces"][0]["NetworkInterfaceId"],
           "quarantine_sg_id": env["QUARANTINE_SG_ID"]}


def test_cryptomining_full_pipeline(ec2_client, iam_client, dynamodb_resource,
                                    sfn_client, test_instance):
    finding = load_fixture("finding_cryptomining.json")
    account_id = finding["detail"]["accountId"]

    # ── PRE-STATE ──────────────────────────────────────────────────────
    resp = ec2_client.describe_instances(InstanceIds=[test_instance["instance_id"]])
    pre_sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert test_instance["quarantine_sg_id"] not in pre_sgs

    # ── TRIGGER ────────────────────────────────────────────────────────
    finding["detail"]["resource"]["instanceDetails"]["instanceId"] = test_instance["instance_id"]
    finding["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["networkInterfaceId"] = test_instance["eni_id"]

    sfn_arn = sfn_client.list_state_machines()["stateMachines"][0]["stateMachineArn"]
    exec_resp = sfn_client.start_execution(
        stateMachineArn=sfn_arn,
        input=json.dumps(finding),
    )
    result = wait_for_execution(sfn_client, exec_resp["executionArn"])
    assert result["status"] == "SUCCEEDED"

    # ── POST-STATE: Network ────────────────────────────────────────────
    resp = ec2_client.describe_instances(InstanceIds=[test_instance["instance_id"]])
    post_sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert post_sgs == [test_instance["quarantine_sg_id"]], \
        f"Expected only QuarantineSG, got: {post_sgs}"

    # ── POST-STATE: Audit ──────────────────────────────────────────────
    table = dynamodb_resource.Table("AegisFlow_ActiveJails")
    resource_arn = f"arn:aws:ec2:us-east-1:{account_id}:instance/{test_instance['instance_id']}"
    item = table.get_item(Key={"resource_arn": resource_arn})["Item"]
    assert item["status"] == "COMPLETE"
    assert item["evidence_collection_status"] in ("success", "partial", "failed")
