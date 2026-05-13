import os, pytest, json
import boto3
from moto import mock_aws
from aegis_remediator.models import RemediationContext

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

def make_compute_ctx(role_name: str) -> RemediationContext:
    return RemediationContext(
        resource_arn=f"arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
        finding_id="f1", finding_type="Impact:EC2/CryptoMining",
        playbook_type="COMPUTE", action="FreezeIdentity",
        instance_id="i-abc", eni_id="eni-abc",
    )

def make_identity_ctx(principal_arn: str) -> RemediationContext:
    return RemediationContext(
        resource_arn=principal_arn,
        finding_id="f2", finding_type="PrivilegeEscalation:IAMUser/AdministrativePermissions",
        playbook_type="IDENTITY", action="FreezeIdentity",
        principal_arn=principal_arn,
    )

@mock_aws
def test_compute_attaches_deny_policy_to_instance_role():
    from aegis_remediator.identity import freeze_identity
    iam = boto3.client("iam", region_name="us-east-1")
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Create role + instance profile + associate with instance
    iam.create_role(RoleName="InstanceRole", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    }))

    ctx = make_compute_ctx("InstanceRole")
    # patch: tell freeze_identity which role to target
    ctx.instance_id = "i-abc"
    ctx._instance_role_name = "InstanceRole"  # set by handler in real flow

    result = freeze_identity(ctx, role_name_override="InstanceRole")
    policies = iam.list_role_policies(RoleName="InstanceRole")["PolicyNames"]
    assert "AegisFlow-Deny-All" in policies
    raw = iam.get_role_policy(RoleName="InstanceRole", PolicyName="AegisFlow-Deny-All")["PolicyDocument"]
    deny_doc = raw if isinstance(raw, dict) else json.loads(raw)
    assert deny_doc["Statement"][0]["Effect"] == "Deny"

@mock_aws
def test_identity_attaches_deny_and_revokes_sts():
    from aegis_remediator.identity import freeze_identity
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="compromised-role", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    }))
    ctx = make_identity_ctx("arn:aws:iam::123456789012:role/compromised-role")
    result = freeze_identity(ctx)
    policies = iam.list_role_policies(RoleName="compromised-role")["PolicyNames"]
    assert "AegisFlow-Deny-All" in policies
    assert result["sts_sessions_revoked"] is True
