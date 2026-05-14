import logging
from .models import RemediationContext
from .validator import validate_event
from .locker import acquire_lock, AlreadyLocked
from .evidence import collect_evidence
from .network import quarantine_network
from .identity import freeze_identity
from .audit import write_audit_record, mark_pr_pending
from .github_pr import create_github_pr
from .failed import handle_remediation_failed

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def handler(event: dict, context) -> dict:
    action = event.get("action", "ValidateEvent")
    raw_context = event.get("context", event)  # Step Functions passes context under "context" key

    if action == "ValidateEvent":
        ctx = validate_event(raw_context)
        return {
            "resource_arn": ctx.resource_arn,
            "finding_id": ctx.finding_id,
            "finding_type": ctx.finding_type,
            "playbook_type": ctx.playbook_type,
            "instance_id": ctx.instance_id,
            "eni_id": ctx.eni_id,
            "principal_arn": ctx.principal_arn,
            "session_context": ctx.session_context,
        }

    # Rebuild context from Step Functions state
    ctx = _context_from_state(event, action)

    if action == "AcquireLock":
        try:
            acquire_lock(ctx)
            return {"locked": True}
        except AlreadyLocked:
            log.info("Resource already locked — duplicate finding, exiting.")
            raise  # Step Functions will mark as FAILED; EventBridge DLQ handles

    if action == "CollectEvidence":
        result = collect_evidence(ctx)
        return result

    if action == "QuarantineNetwork":
        return quarantine_network(ctx)

    if action == "FreezeIdentity":
        return freeze_identity(ctx)

    if action == "WriteAuditRecord":
        state = event.get("context", event)  # Step Functions execution state lives here
        action_log = {
            "network": state.get("networkResult", {}).get("Payload", {}),
            "identity": state.get("identityResult", {}).get("Payload", {}),
        }
        evidence = state.get("evidenceResult", {}).get("Payload", {})
        write_audit_record(
            ctx, action_log,
            evidence_status=evidence.get("evidence_collection_status", "unknown"),
            evidence_uris=evidence.get("evidence_s3_uris", []),
        )
        return {"audit_written": True}

    if action == "CreateGitHubPR":
        state = event.get("context", event)
        audit_record = state.get("auditResult", {}).get("Payload", {})
        result = create_github_pr(ctx, audit_record)
        if not result.get("pr_created"):
            mark_pr_pending(ctx)
        return result

    if action == "RemediationFailed":
        return handle_remediation_failed(ctx, event)

    raise ValueError(f"Unknown action: {action}")

def _context_from_state(event: dict, action: str) -> RemediationContext:
    ctx_data = event.get("context", {})
    if isinstance(ctx_data, dict) and "Payload" in ctx_data:
        ctx_data = ctx_data["Payload"]
    elif isinstance(ctx_data, dict) and "context" in ctx_data:
        nested_context = ctx_data.get("context", {})
        if isinstance(nested_context, dict) and "Payload" in nested_context:
            ctx_data = nested_context["Payload"]
    return RemediationContext(
        resource_arn=ctx_data.get("resource_arn", ""),
        finding_id=ctx_data.get("finding_id", ""),
        finding_type=ctx_data.get("finding_type", ""),
        playbook_type=ctx_data.get("playbook_type", "COMPUTE"),
        action=action,
        instance_id=ctx_data.get("instance_id", ""),
        eni_id=ctx_data.get("eni_id", ""),
        principal_arn=ctx_data.get("principal_arn", ""),
        session_context=ctx_data.get("session_context", {}),
    )
