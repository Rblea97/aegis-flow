"""
Provides boto3 sessions scoped to the AegisFlow Remediation Execution Role.

The Lambda's own IAM role (RemediatorLambdaRole) intentionally has no direct
AWS permissions — it can only call sts:AssumeRole. All real AWS operations must
use the credentials vended by assuming the Execution Role (EXECUTION_ROLE_ARN).

Usage:
    from .session import get_client, get_resource

    iam = get_client("iam")
    ddb = get_resource("dynamodb")
"""

import os
import logging
import boto3
from boto3 import Session

log = logging.getLogger(__name__)

_assumed_session: Session | None = None


def _build_assumed_session() -> Session:
    """Assume the Execution Role and return a boto3 Session with those credentials."""
    execution_role_arn = os.environ["EXECUTION_ROLE_ARN"]
    sts = boto3.client("sts")
    resp = sts.assume_role(
        RoleArn=execution_role_arn,
        RoleSessionName="aegisflow-remediator",
    )
    creds = resp["Credentials"]
    log.info("Assumed execution role %s (expiry: %s)", execution_role_arn, creds["Expiration"])
    return Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-west-1"),
    )


def _get_assumed_session() -> Session:
    """Return (or lazily create) the module-level assumed Session.

    Lambda containers are reused across invocations; the session is created
    once per container. Credentials are valid for 1 hour by default — well
    within any single Lambda execution window.
    """
    global _assumed_session
    if _assumed_session is None:
        _assumed_session = _build_assumed_session()
    return _assumed_session


def get_client(service: str, **kwargs):
    """Return a boto3 client for *service* using the assumed Execution Role."""
    return _get_assumed_session().client(service, **kwargs)


def get_resource(service: str, **kwargs):
    """Return a boto3 resource for *service* using the assumed Execution Role."""
    return _get_assumed_session().resource(service, **kwargs)


def reset_session() -> None:
    """Force session refresh on next call. Useful in tests."""
    global _assumed_session
    _assumed_session = None
