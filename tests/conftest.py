import boto3
import pytest

LOCALSTACK_ENDPOINT = "http://localhost:4566"
AWS_REGION = "us-east-1"
FAKE_CREDS = {"aws_access_key_id": "test", "aws_secret_access_key": "test",
              "region_name": AWS_REGION, "endpoint_url": LOCALSTACK_ENDPOINT}

@pytest.fixture(scope="session")
def localstack():
    """Verify LocalStack is running before integration tests."""
    import urllib.request
    try:
        urllib.request.urlopen(f"{LOCALSTACK_ENDPOINT}/_localstack/health", timeout=3)
    except Exception:
        pytest.skip("LocalStack not running — start with: docker compose up -d")

@pytest.fixture
def ec2_client(localstack):
    return boto3.client("ec2", **FAKE_CREDS)

@pytest.fixture
def iam_client(localstack):
    return boto3.client("iam", **FAKE_CREDS)

@pytest.fixture
def dynamodb_resource(localstack):
    return boto3.resource("dynamodb", **FAKE_CREDS)

@pytest.fixture
def sfn_client(localstack):
    return boto3.client("stepfunctions", **FAKE_CREDS)

@pytest.fixture
def events_client(localstack):
    return boto3.client("events", **FAKE_CREDS)
