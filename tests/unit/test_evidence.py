import os, pytest
import boto3
from moto import mock_aws
from aegis_remediator.models import RemediationContext

os.environ.setdefault("FORENSICS_BUCKET", "aegisflow-forensics-test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

def make_ctx(playbook: str) -> RemediationContext:
    return RemediationContext(
        resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
        finding_id="f1", finding_type="Impact:EC2/CryptoMining",
        playbook_type=playbook, action="CollectEvidence",
        instance_id="i-abc", eni_id="eni-abc",
        principal_arn="arn:aws:iam::123456789012:user/u" if playbook == "IDENTITY" else "",
    )

@mock_aws
def test_compute_evidence_returns_status_field():
    from aegis_remediator.evidence import collect_evidence
    # Set up S3
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="aegisflow-forensics-test")
    # Set up EC2: VPC → subnet → instance with EBS volume
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    reservation = ec2.run_instances(
        ImageId="ami-00000000",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["SubnetId"],
        BlockDeviceMappings=[{
            "DeviceName": "/dev/xvda",
            "Ebs": {"VolumeSize": 8, "DeleteOnTermination": True},
        }],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx = RemediationContext(
        resource_arn=f"arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}",
        finding_id="f1", finding_type="Impact:EC2/CryptoMining",
        playbook_type="COMPUTE", action="CollectEvidence",
        instance_id=instance_id, eni_id="eni-abc",
    )
    result = collect_evidence(ctx)
    assert "evidence_collection_status" in result
    assert result["evidence_collection_status"] in ("success", "partial", "failed")
    assert "evidence_s3_uris" in result

@mock_aws
def test_identity_evidence_returns_status_field():
    from aegis_remediator.evidence import collect_evidence
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="aegisflow-forensics-test")
    result = collect_evidence(make_ctx("IDENTITY"))
    assert "evidence_collection_status" in result
    assert result["evidence_collection_status"] in ("success", "partial", "failed")
    assert "evidence_s3_uris" in result
