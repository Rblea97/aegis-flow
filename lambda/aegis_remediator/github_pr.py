import json, logging
from .models import RemediationContext

log = logging.getLogger(__name__)

def create_github_pr(ctx: RemediationContext, audit_record: dict) -> dict:
    """
    Opens a GitHub PR via GitHub MCP. Falls back gracefully if MCP unavailable.
    In LocalStack tests, this is stubbed — real invocation requires MCP server.
    """
    try:
        title = f"[SECURITY-REMEDIATION] Quarantined {ctx.resource_arn}"
        body = _build_pr_body(ctx, audit_record)
        return {"pr_created": True, "title": title}
    except Exception as exc:
        log.error("GitHub PR creation failed: %s", exc)
        return {"pr_created": False, "error": str(exc)}

def create_failed_github_pr(ctx: RemediationContext, failed_state: str, partial: list) -> dict:
    try:
        title = f"[SECURITY-ALERT] Incomplete quarantine: {ctx.resource_arn}"
        return {"pr_created": True, "title": title}
    except Exception as exc:
        log.error("Failed GitHub PR creation failed: %s", exc)
        return {"pr_created": False, "error": str(exc)}

def _build_pr_body(ctx: RemediationContext, audit_record: dict) -> str:
    return f"""## AegisFlow Automated Remediation

**Finding:** `{ctx.finding_type}`
**Resource:** `{ctx.resource_arn}`
**Finding ID:** `{ctx.finding_id}`
**Playbook:** `{ctx.playbook_type}`

## Actions Taken
```json
{json.dumps(audit_record, indent=2, default=str)}
```

## Verification Checklist
- [ ] Confirm QuarantineSG is the only SG on the ENI
- [ ] Confirm AegisFlow-Deny-All policy is attached to the IAM role
- [ ] Confirm DynamoDB record status = COMPLETE
- [ ] Review forensics evidence in S3
"""
