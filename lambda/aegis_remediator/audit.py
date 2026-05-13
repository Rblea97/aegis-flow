import os, logging
from datetime import datetime, timezone
import boto3
from .models import RemediationContext

log = logging.getLogger(__name__)
TABLE_NAME = os.environ["ACTIVE_JAILS_TABLE"]

def write_audit_record(ctx: RemediationContext, action_log: dict,
                        evidence_status: str, evidence_uris: list) -> None:
    table = boto3.resource("dynamodb").Table(TABLE_NAME)
    table.update_item(
        Key={"resource_arn": ctx.resource_arn},
        UpdateExpression=(
            "SET #s = :s, action_log = :al, evidence_collection_status = :es, "
            "evidence_s3_uris = :eu, remediated_at = :ra, github_pr_pending = :gpp"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "COMPLETE",
            ":al": action_log,
            ":es": evidence_status,
            ":eu": evidence_uris,
            ":ra": datetime.now(timezone.utc).isoformat(),
            ":gpp": False,
        },
    )

def write_failed_record(ctx: RemediationContext, failed_state: str,
                         failure_reason: str, partial: list) -> None:
    table = boto3.resource("dynamodb").Table(TABLE_NAME)
    table.update_item(
        Key={"resource_arn": ctx.resource_arn},
        UpdateExpression=(
            "SET #s = :s, failed_state = :fs, failure_reason = :fr, "
            "partial_actions_completed = :pa, remediated_at = :ra"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "ERROR",
            ":fs": failed_state,
            ":fr": failure_reason,
            ":pa": partial,
            ":ra": datetime.now(timezone.utc).isoformat(),
        },
    )

def mark_pr_pending(ctx: RemediationContext) -> None:
    table = boto3.resource("dynamodb").Table(TABLE_NAME)
    table.update_item(
        Key={"resource_arn": ctx.resource_arn},
        UpdateExpression="SET github_pr_pending = :t",
        ExpressionAttributeValues={":t": True},
    )
