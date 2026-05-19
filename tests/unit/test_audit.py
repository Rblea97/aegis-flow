import os
import time

import boto3
import pytest
from aegis_remediator.models import RemediationContext
from moto import mock_aws

os.environ.setdefault("ACTIVE_JAILS_TABLE", "AegisFlow_ActiveJails")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

@pytest.fixture
def locked_table():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName="AegisFlow_ActiveJails",
            KeySchema=[{"AttributeName": "resource_arn", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "resource_arn", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        table = boto3.resource("dynamodb", region_name="us-east-1").Table("AegisFlow_ActiveJails")
        table.put_item(Item={
            "resource_arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
            "status": "LOCKED", "finding_id": "f1",
            "ttl": int(time.time()) + 86400,
        })
        yield table

def test_write_audit_record_sets_complete(locked_table):
    from aegis_remediator.audit import write_audit_record
    ctx = RemediationContext(
        resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
        finding_id="f1", finding_type="Impact:EC2/CryptoMining",
        playbook_type="COMPUTE", action="WriteAuditRecord",
        instance_id="i-abc", eni_id="eni-abc",
    )
    action_log = {"network": {"action_taken": "sg_swapped"}, "identity": {"action_taken": "deny_policy_attached"}}
    write_audit_record(ctx, action_log, evidence_status="success", evidence_uris=["s3://bucket/key"])
    item = locked_table.get_item(Key={"resource_arn": ctx.resource_arn})["Item"]
    assert item["status"] == "COMPLETE"
    assert item["evidence_collection_status"] == "success"

def test_write_failed_record_sets_error(locked_table):
    from aegis_remediator.audit import write_failed_record
    ctx = RemediationContext(
        resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
        finding_id="f1", finding_type="Impact:EC2/CryptoMining",
        playbook_type="COMPUTE", action="RemediationFailed",
        instance_id="i-abc", eni_id="eni-abc",
    )
    write_failed_record(ctx, failed_state="QuarantineNetwork",
                        failure_reason="AccessDenied", partial=["CollectEvidence"])
    item = locked_table.get_item(Key={"resource_arn": ctx.resource_arn})["Item"]
    assert item["status"] == "ERROR"
    assert item["failed_state"] == "QuarantineNetwork"
    assert "CollectEvidence" in item["partial_actions_completed"]
