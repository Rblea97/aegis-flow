from aegis_remediator.github_pr import create_github_pr
from aegis_remediator.models import RemediationContext


def test_create_github_pr_returns_pending_manual_trail():
    ctx = RemediationContext(
        resource_arn="arn:aws:iam::123456789012:role/compromised-role",
        finding_id="finding-1",
        finding_type="PrivilegeEscalation:IAMUser/AdministrativePermissions",
        playbook_type="IDENTITY",
        action="CreateGitHubPR",
    )

    result = create_github_pr(ctx, {"audit_written": True})

    assert result["pr_created"] is False
    assert result["pr_pending"] is True
    assert "SECURITY-REMEDIATION" in result["title"]
    assert "finding-1" in result["body"]
