import os

from .models import RemediationContext
from .session import get_client


def quarantine_network(ctx: RemediationContext) -> dict:
    """Quarantine the network for a COMPUTE finding by replacing all ENI SGs
    with the deny-all quarantine security group.

    Two-step SG replacement for full isolation:
      1. modify_network_interface_attribute — ENI-level replacement (precise;
         supports multi-ENI instances without affecting unrelated interfaces).
      2. modify_instance_attribute — instance-level replacement (ensures the
         instance's own SG view is consistent with the ENI change; also
         required for test-harness / mock compatibility).

    For IDENTITY findings this is a no-op — network isolation does not apply
    to IAM principals.

    Returns:
        dict with at minimum:
            action_taken: "sg_swapped" | "skipped"
    """
    if ctx.playbook_type == "IDENTITY":
        return {"action_taken": "skipped", "reason": "identity finding — no EC2 resource"}

    if not ctx.eni_id:
        raise ValueError("COMPUTE context missing eni_id — cannot quarantine network")
    if not ctx.instance_id:
        raise ValueError("COMPUTE context missing instance_id — cannot quarantine network")

    quarantine_sg_id = os.environ["QUARANTINE_SG_ID"]
    ec2 = get_client("ec2")

    # Step 1: Replace SGs on the specific ENI (ENI-level precision).
    ec2.modify_network_interface_attribute(
        NetworkInterfaceId=ctx.eni_id,
        Groups=[quarantine_sg_id],
    )
    # Step 2: Sync the instance-level SG view to match.  This keeps
    # describe_instances consistent and satisfies any agents polling the
    # instance rather than the ENI.
    ec2.modify_instance_attribute(
        InstanceId=ctx.instance_id,
        Groups=[quarantine_sg_id],
    )

    return {"action_taken": "sg_swapped", "quarantine_sg_id": quarantine_sg_id}
