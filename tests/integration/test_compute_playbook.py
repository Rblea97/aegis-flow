import json
import time
import pytest
from pathlib import Path
from botocore.exceptions import ClientError

FIXTURES = Path(__file__).parent.parent / "fixtures"
ENDPOINT = "http://localhost:4566"
CREDS = {"aws_access_key_id": "test", "aws_secret_access_key": "test",
          "region_name": "us-east-1", "endpoint_url": ENDPOINT}


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def wait_for_audit_record(table, resource_arn: str, timeout: int = 10) -> dict:
    start = time.time()
    while time.time() - start < timeout:
        response = table.get_item(Key={"resource_arn": resource_arn})
        item = response.get("Item")
        if item and item.get("status") == "COMPLETE":
            elapsed = time.time() - start
            assert elapsed <= 5, f"Remediation took {elapsed:.1f}s — DoD requires ≤ 5s"
            return item
        time.sleep(0.5)
    pytest.fail(f"Audit record for {resource_arn} did not reach COMPLETE within {timeout}s")


@pytest.fixture
def test_instance(ec2_client, iam_client):
    """Provision an EC2 test target inside the CDK-created LocalStack VPC."""
    quarantine_sg = _find_quarantine_sg(ec2_client)
    vpc_id = quarantine_sg["VpcId"]
    subnet_id = _find_subnet_id(ec2_client, vpc_id)
    web_sg_id = _ensure_web_sg(ec2_client, vpc_id)
    role_name = "aegisflow-test-instance-role"
    profile_name = "aegisflow-test-instance-profile"
    _ensure_instance_profile(iam_client, role_name, profile_name)

    instance = ec2_client.run_instances(
        ImageId="ami-00000000",
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[web_sg_id],
        SubnetId=subnet_id,
        IamInstanceProfile={"Name": profile_name},
    )["Instances"][0]
    yield {
        "instance_id": instance["InstanceId"],
        "eni_id": instance["NetworkInterfaces"][0]["NetworkInterfaceId"],
        "quarantine_sg_id": quarantine_sg["GroupId"],
        "role_name": role_name,
    }


def _find_quarantine_sg(ec2_client) -> dict:
    groups = ec2_client.describe_security_groups()["SecurityGroups"]
    matches = [
        group for group in groups
        if group.get("Description") == "AegisFlow quarantine — deny all traffic"
    ]
    assert matches, "Quarantine security group was not deployed by CDK"
    return matches[0]


def _find_subnet_id(ec2_client, vpc_id: str) -> str:
    subnets = ec2_client.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"]
    assert subnets, f"No subnets found in CDK VPC {vpc_id}"
    return subnets[0]["SubnetId"]


def _ensure_web_sg(ec2_client, vpc_id: str) -> str:
    groups = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["WebTier-SG"]},
        ]
    )["SecurityGroups"]
    if groups:
        return groups[0]["GroupId"]

    return ec2_client.create_security_group(
        GroupName="WebTier-SG",
        Description="Web tier test fixture",
        VpcId=vpc_id,
    )["GroupId"]


def _ensure_instance_profile(iam_client, role_name: str, profile_name: str) -> None:
    assume_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    try:
        iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_policy)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise

    try:
        iam_client.create_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise

    try:
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in {"LimitExceeded", "EntityAlreadyExists"}:
            raise


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
    resource_arn = f"arn:aws:ec2:us-east-1:{account_id}:instance/{test_instance['instance_id']}"
    table = dynamodb_resource.Table("AegisFlow_ActiveJails")

    sfn_arn = sfn_client.list_state_machines()["stateMachines"][0]["stateMachineArn"]
    sfn_client.start_execution(
        stateMachineArn=sfn_arn,
        input=json.dumps(finding),
    )
    item = wait_for_audit_record(table, resource_arn)

    # ── POST-STATE: Network ────────────────────────────────────────────
    resp = ec2_client.describe_instances(InstanceIds=[test_instance["instance_id"]])
    post_sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert post_sgs == [test_instance["quarantine_sg_id"]], \
        f"Expected only QuarantineSG, got: {post_sgs}"

    # ── POST-STATE: Audit ──────────────────────────────────────────────
    assert item["status"] == "COMPLETE"
    assert item["evidence_collection_status"] in ("success", "partial", "failed")

    policies = iam_client.list_role_policies(RoleName=test_instance["role_name"])["PolicyNames"]
    assert "AegisFlow-Deny-All" in policies
