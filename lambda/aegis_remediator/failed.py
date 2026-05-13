import logging, os
import boto3
from .models import RemediationContext
from .audit import write_failed_record
from .github_pr import create_failed_github_pr

log = logging.getLogger(__name__)
SNS_TOPIC_ARN = os.environ.get("SNS_ALERT_TOPIC_ARN", "")

def handle_remediation_failed(ctx: RemediationContext, event: dict) -> dict:
    state = event.get("context", event)  # Step Functions execution state lives here
    failed_state = state.get("error", {}).get("Error", "UnknownError")
    failure_reason = state.get("error", {}).get("Cause", "Unknown")
    partial = _extract_partial_actions(state)

    write_failed_record(ctx, failed_state=failed_state,
                        failure_reason=failure_reason, partial=partial)

    if SNS_TOPIC_ARN:
        try:
            boto3.client("sns").publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"[AEGISFLOW ALERT] Incomplete quarantine: {ctx.resource_arn}",
                Message=f"State {failed_state} failed.\nReason: {failure_reason}\n"
                        f"Partial actions: {partial}\nFinding: {ctx.finding_id}",
            )
        except Exception as exc:
            log.error("SNS alert failed: %s", exc)

    create_failed_github_pr(ctx, failed_state=failed_state, partial=partial)
    return {"remediation_failed": True, "failed_state": failed_state}

def _extract_partial_actions(state: dict) -> list:
    completed = []
    for key in ("networkResult", "evidenceResult", "lockResult"):
        if key in state:
            completed.append(key.replace("Result", ""))
    return completed
