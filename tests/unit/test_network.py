import os, pytest
import boto3
from moto import mock_aws
from aegis_remediator.models import RemediationContext

os.environ.setdefault("QUARANTINE_SG_ID", "sg-quarantine")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

@pytest.fixture
def ec2_with_instance():
    with mock_aws():
        ec2 = boto3.resource("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/24")
        web_sg = ec2.create_security_group(GroupName="WebTier-SG", Description="web", VpcId=vpc.id)
        quarantine_sg = ec2.create_security_group(
            GroupName="Quarantine-SG", Description="quarantine", VpcId=vpc.id
        )
        # patch QUARANTINE_SG_ID to the actual created SG id
        os.environ["QUARANTINE_SG_ID"] = quarantine_sg.id
        instance = ec2.create_instances(
            ImageId="ami-00000000", MinCount=1, MaxCount=1,
            SecurityGroupIds=[web_sg.id], SubnetId=subnet.id,
        )[0]
        yield {"instance": instance, "web_sg": web_sg, "quarantine_sg": quarantine_sg}

def test_compute_quarantine_swaps_sg(ec2_with_instance):
    from aegis_remediator.network import quarantine_network
    inst = ec2_with_instance["instance"]
    eni_id = inst.network_interfaces_attribute[0]["NetworkInterfaceId"]
    ctx = RemediationContext(
        resource_arn=f"arn:aws:ec2:us-east-1:123456789012:instance/{inst.id}",
        finding_id="f1", finding_type="Impact:EC2/CryptoMining",
        playbook_type="COMPUTE", action="QuarantineNetwork",
        instance_id=inst.id, eni_id=eni_id,
    )
    result = quarantine_network(ctx)
    inst.reload()
    sg_ids = [sg["GroupId"] for sg in inst.security_groups]
    assert sg_ids == [os.environ["QUARANTINE_SG_ID"]]
    assert result["action_taken"] == "sg_swapped"

def test_identity_quarantine_is_noop():
    from aegis_remediator.network import quarantine_network
    ctx = RemediationContext(
        resource_arn="arn:aws:iam::123456789012:user/u",
        finding_id="f1", finding_type="UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        playbook_type="IDENTITY", action="QuarantineNetwork",
        principal_arn="arn:aws:iam::123456789012:user/u",
    )
    result = quarantine_network(ctx)
    assert result["action_taken"] == "skipped"
