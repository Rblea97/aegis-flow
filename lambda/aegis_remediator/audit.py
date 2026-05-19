import logging
import os
from datetime import UTC, datetime

from .models import RemediationContext
from .session import get_resource

log = logging.getLogger(__name__)
TABLE_NAME = os.environ["ACTIVE_JAILS_TABLE"]

def write_audit_record(ctx: RemediationContext, action_log: dict,
                        evidence_status: str, evidence_uris: list) -> None:
    table = get_resource("dynamodb").Table(TABLE_NAME)
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
            ":ra": datetime.now(UTC).isoformat(),
            ":gpp": False,
        },
    )

def write_failed_record(ctx: RemediationContext, failed_state: str,
                         failure_reason: str, partial: list) -> None:
    table = get_resource("dynamodb").Table(TABLE_NAME)
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
            ":ra": datetime.now(UTC).isoformat(),
        },
    )

def mark_pr_pending(ctx: RemediationContext) -> None:
    table = get_resource("dynamodb").Table(TABLE_NAME)
    table.update_item(
        Key={"resource_arn": ctx.resource_arn},
        UpdateExpression="SET github_pr_pending = :t",
        ExpressionAttributeValues={":t": True},
    )
