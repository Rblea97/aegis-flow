#!/usr/bin/env python3
"""
Boto3 audit script — verifies post-remediation state against LocalStack or AWS.
Fulfills DoD requirement: "All infrastructure state changes are verified via
an automated Boto3 audit script."

Usage:
    python scripts/verify_remediation.py --resource-arn <arn> [--endpoint http://localhost:4566]
"""
import argparse
import sys

import boto3
from botocore.exceptions import ClientError


def run_audit(resource_arn: str, endpoint: str, quarantine_sg_id: str, table_name: str) -> bool:
    creds = dict(endpoint_url=endpoint, region_name="us-east-1",
                 aws_access_key_id="test", aws_secret_access_key="test") if endpoint else {}
    ec2 = boto3.client("ec2", **creds)
    iam = boto3.client("iam", **creds)
    ddb = boto3.resource("dynamodb", **creds).Table(table_name)

    passed = True
    print(f"\n{'='*60}")
    print(f"AegisFlow Remediation Audit — {resource_arn}")
    print(f"{'='*60}")

    item = ddb.get_item(Key={"resource_arn": resource_arn}).get("Item")
    if not item:
        print("FAIL: No DynamoDB record found")
        return False

    status = item.get("status")
    status_ok = status == "COMPLETE"
    print(f"{'PASS' if status_ok else 'FAIL'} DynamoDB status: {status}")
    passed = passed and status_ok

    playbook = item.get("playbook_type", "COMPUTE")

    if playbook == "COMPUTE":
        instance_id = resource_arn.split("/")[-1]
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
            sg_ok = sgs == [quarantine_sg_id]
            print(f"{'PASS' if sg_ok else 'FAIL'} Security Groups: {sgs}")
            passed = passed and sg_ok
        except (ClientError, IndexError, KeyError) as e:
            print(f"FAIL EC2 check failed: {e}")
            passed = False

    elif playbook == "IDENTITY":
        principal_arn = resource_arn
        principal_name = principal_arn.split("/")[-1]
        resource_type = principal_arn.split(":")[5].split("/")[0]
        try:
            if resource_type == "role":
                policies = iam.list_role_policies(RoleName=principal_name)["PolicyNames"]
            else:
                policies = iam.list_user_policies(UserName=principal_name)["PolicyNames"]
            deny_ok = "AegisFlow-Deny-All" in policies
            print(f"{'PASS' if deny_ok else 'FAIL'} IAM Deny-All policy: {'present' if deny_ok else 'MISSING'}")
            passed = passed and deny_ok
        except (ClientError, KeyError) as e:
            print(f"FAIL IAM check failed: {e}")
            passed = False

    ev_status = item.get("evidence_collection_status", "unknown")
    ev_ok = ev_status != "unknown"
    print(f"{'PASS' if ev_ok else 'FAIL'} Evidence collection: {ev_status}")
    passed = passed and ev_ok

    print(f"\n{'AUDIT PASSED' if passed else 'AUDIT FAILED'}\n")
    return passed


def main():
    parser = argparse.ArgumentParser(description="AegisFlow post-remediation audit")
    parser.add_argument("--resource-arn", required=True)
    parser.add_argument("--endpoint", default="",
                        help="Override boto3 endpoint (e.g. http://localhost:4566 for LocalStack)")
    parser.add_argument("--quarantine-sg-id", default="")
    parser.add_argument("--table-name", default="AegisFlow_ActiveJails")
    args = parser.parse_args()
    ok = run_audit(args.resource_arn, args.endpoint, args.quarantine_sg_id, args.table_name)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
