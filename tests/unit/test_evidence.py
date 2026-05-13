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
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="aegisflow-forensics-test")
    result = collect_evidence(make_ctx("COMPUTE"))
    assert "evidence_collection_status" in result
    assert result["evidence_collection_status"] in ("success", "partial", "failed")

@mock_aws
def test_identity_evidence_returns_status_field():
    from aegis_remediator.evidence import collect_evidence
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="aegisflow-forensics-test")
    result = collect_evidence(make_ctx("IDENTITY"))
    assert "evidence_collection_status" in result
