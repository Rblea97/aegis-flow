import json
import os
import logging
import datetime
import boto3

from .models import RemediationContext

log = logging.getLogger(__name__)
FORENSICS_BUCKET = os.environ["FORENSICS_BUCKET"]


def collect_evidence(ctx: RemediationContext) -> dict:
    """Best-effort evidence collector. Never raises.

    Returns a dict with at minimum:
        evidence_collection_status: "success" | "partial" | "failed"
        evidence_s3_uris: list[str]
    """
    try:
        if ctx.playbook_type == "COMPUTE":
            return _collect_compute_evidence(ctx)
        return _collect_identity_evidence(ctx)
    except Exception as exc:
        log.error("Evidence collection failed: %s", exc)
        return {"evidence_collection_status": "failed", "evidence_s3_uris": []}


def _collect_compute_evidence(ctx: RemediationContext) -> dict:
    s3 = boto3.client("s3")
    ec2 = boto3.client("ec2")
    uris: list[str] = []
    try:
        resp = ec2.describe_instances(InstanceIds=[ctx.instance_id])
        volumes = [
            bdm["Ebs"]["VolumeId"]
            for r in resp["Reservations"]
            for i in r["Instances"]
            for bdm in i.get("BlockDeviceMappings", [])
            if "Ebs" in bdm
        ]
        for vol_id in volumes:
            snap = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"AegisFlow evidence {ctx.finding_id}",
            )
            meta_key = f"evidence/{ctx.finding_id}/snapshot-{vol_id}.json"
            s3.put_object(
                Bucket=FORENSICS_BUCKET,
                Key=meta_key,
                Body=json.dumps({"snapshot_id": snap["SnapshotId"], "volume_id": vol_id}),
            )
            uris.append(f"s3://{FORENSICS_BUCKET}/{meta_key}")
    except Exception as exc:
        log.warning("Partial evidence collection for COMPUTE: %s", exc)
        return {"evidence_collection_status": "partial", "evidence_s3_uris": uris}
    return {"evidence_collection_status": "success", "evidence_s3_uris": uris}


def _collect_identity_evidence(ctx: RemediationContext) -> dict:
    s3 = boto3.client("s3")
    cloudtrail = boto3.client("cloudtrail")
    end = datetime.datetime.now(datetime.timezone.utc)
    start = end - datetime.timedelta(hours=2)
    try:
        username = ctx.principal_arn.split("/")[-1]
        events = cloudtrail.lookup_events(
            LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": username}],
            StartTime=start,
            EndTime=end,
        ).get("Events", [])
        key = f"evidence/{ctx.finding_id}/cloudtrail-export.json"
        s3.put_object(
            Bucket=FORENSICS_BUCKET,
            Key=key,
            Body=json.dumps(events, default=str),
        )
        uri = f"s3://{FORENSICS_BUCKET}/{key}"
    except Exception as exc:
        log.warning("Partial evidence collection for IDENTITY: %s", exc)
        return {"evidence_collection_status": "partial", "evidence_s3_uris": []}
    return {"evidence_collection_status": "success", "evidence_s3_uris": [uri]}
