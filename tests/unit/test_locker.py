import os

import boto3
import pytest
from aegis_remediator.models import RemediationContext
from moto import mock_aws

os.environ.setdefault("ACTIVE_JAILS_TABLE", "AegisFlow_ActiveJails")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

@pytest.fixture
def ddb_table():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName="AegisFlow_ActiveJails",
            KeySchema=[{"AttributeName": "resource_arn", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "resource_arn", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield boto3.resource("dynamodb", region_name="us-east-1").Table("AegisFlow_ActiveJails")

def make_ctx(arn: str = "arn:aws:ec2:us-east-1:123456789012:instance/i-abc") -> RemediationContext:
    return RemediationContext(
        resource_arn=arn, finding_id="f1", finding_type="Impact:EC2/CryptoMining",
        playbook_type="COMPUTE", action="AcquireLock", instance_id="i-abc", eni_id="eni-abc",
    )

def test_acquire_lock_writes_locked_status(ddb_table):
    from aegis_remediator.locker import acquire_lock
    ctx = make_ctx()
    acquire_lock(ctx)
    item = ddb_table.get_item(Key={"resource_arn": ctx.resource_arn})["Item"]
    assert item["status"] == "LOCKED"
    assert item["finding_id"] == "f1"
    assert "ttl" in item

def test_acquire_lock_raises_on_duplicate(ddb_table):
    from aegis_remediator.locker import AlreadyLocked, acquire_lock
    ctx = make_ctx()
    acquire_lock(ctx)
    with pytest.raises(AlreadyLocked):
        acquire_lock(ctx)
