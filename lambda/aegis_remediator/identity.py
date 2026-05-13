import json
import logging
from datetime import datetime, timezone

import boto3

from .models import RemediationContext

log = logging.getLogger(__name__)

DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "DateLessThan": {
                "aws:TokenIssueTime": datetime.now(timezone.utc).isoformat()
            }
        },
    }],
})


def freeze_identity(ctx: RemediationContext, role_name_override: str = "") -> dict:
    iam = boto3.client("iam")

    if ctx.playbook_type == "COMPUTE":
        role_name = role_name_override or _get_instance_role(ctx.instance_id)
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="AegisFlow-Deny-All",
            PolicyDocument=DENY_ALL_POLICY,
        )
        return {"action_taken": "deny_policy_attached", "target": role_name, "sts_sessions_revoked": False}

    # IDENTITY playbook
    principal_arn = ctx.principal_arn
    resource_type = principal_arn.split(":")[5].split("/")[0]  # "role" or "user"
    principal_name = principal_arn.split("/")[-1]

    if resource_type not in ("role", "user"):
        raise ValueError(f"Unsupported principal type '{resource_type}' in ARN: {principal_arn}")

    if resource_type == "role":
        iam.put_role_policy(RoleName=principal_name, PolicyName="AegisFlow-Deny-All",
                            PolicyDocument=DENY_ALL_POLICY)
    else:
        iam.put_user_policy(UserName=principal_name, PolicyName="AegisFlow-Deny-All",
                            PolicyDocument=DENY_ALL_POLICY)

    return {"action_taken": "deny_policy_attached_with_sts_revocation",
            "target": principal_arn, "sts_sessions_revoked": True}


def _get_instance_role(instance_id: str) -> str:
    ec2 = boto3.client("ec2")
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp["Reservations"][0]["Instances"][0]
    profile = instance.get("IamInstanceProfile")
    if not profile:
        raise ValueError(f"Instance {instance_id} has no IAM instance profile attached")
    profile_name = profile["Arn"].split("/")[-1]
    iam = boto3.client("iam")
    return iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"][0]["RoleName"]
