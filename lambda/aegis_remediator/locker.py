import os, time, boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from .models import RemediationContext

TABLE_NAME = os.environ["ACTIVE_JAILS_TABLE"]
TTL_SECONDS = 86_400  # 24h


class AlreadyLocked(Exception):
    pass


def acquire_lock(ctx: RemediationContext) -> None:
    table = boto3.resource("dynamodb").Table(TABLE_NAME)
    try:
        table.put_item(
            Item={
                "resource_arn": ctx.resource_arn,
                "status": "LOCKED",
                "playbook_type": ctx.playbook_type,
                "finding_id": ctx.finding_id,
                "finding_type": ctx.finding_type,
                "ttl": int(time.time()) + TTL_SECONDS,
            },
            ConditionExpression=Attr("resource_arn").not_exists(),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise AlreadyLocked(f"Resource already locked: {ctx.resource_arn}")
        raise
