import re
from .models import RemediationContext

RESOURCE_ARN_PATTERN = re.compile(
    r'^arn:aws:(ec2|iam):[a-z0-9-]*:[0-9]{12}:(instance|role|user)/[\w+=,.@/-]{1,256}$'
)
COMPUTE_PREFIXES = ("Impact:EC2/CryptoMining",)
IDENTITY_PREFIXES = (
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess",
    "PrivilegeEscalation:IAMUser/AdministrativePermissions",
)

def validate_event(event: dict) -> RemediationContext:
    detail = event.get("detail", {})
    finding_type = detail.get("type", "")
    finding_id = detail.get("id", "")
    region = detail.get("region", "")
    account_id = detail.get("accountId", "")

    if finding_type.startswith(COMPUTE_PREFIXES):
        try:
            instance_id = detail["resource"]["instanceDetails"]["instanceId"]
            eni_id = detail["resource"]["instanceDetails"]["networkInterfaces"][0]["networkInterfaceId"]
        except KeyError:
            raise ValueError("Malformed event: missing required field")
        resource_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
        if not RESOURCE_ARN_PATTERN.match(resource_arn):
            raise ValueError(f"ARN failed validation: {resource_arn}")
        return RemediationContext(
            resource_arn=resource_arn,
            finding_id=finding_id,
            finding_type=finding_type,
            playbook_type="COMPUTE",
            action=event.get("action", "ValidateEvent"),
            instance_id=instance_id,
            eni_id=eni_id,
        )

    if finding_type.startswith(IDENTITY_PREFIXES):
        try:
            principal_arn = detail["resource"]["accessKeyDetails"]["userArn"]
            session_context = detail["resource"]["accessKeyDetails"].get("sessionContext", {})
        except KeyError:
            raise ValueError("Malformed event: missing required field")
        if not RESOURCE_ARN_PATTERN.match(principal_arn):
            raise ValueError(f"Rejected: ARN failed validation: {principal_arn}")
        return RemediationContext(
            resource_arn=principal_arn,
            finding_id=finding_id,
            finding_type=finding_type,
            playbook_type="IDENTITY",
            action=event.get("action", "ValidateEvent"),
            principal_arn=principal_arn,
            session_context=session_context,
        )

    raise ValueError(f"Unsupported finding type: {finding_type}")
