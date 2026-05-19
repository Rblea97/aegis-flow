# Aegis-Flow V1 Demo

This demo shows the V1 release without using a real AWS account. It uses moto for fast unit tests and LocalStack for integration tests against AWS-like state.

## What You Will See

The demo validates the core remediation story:

1. A GuardDuty-style finding targets an EC2 instance or IAM principal.
2. The workflow validates the finding and acquires a DynamoDB lock.
3. Evidence collection runs before enforcement.
4. The affected resource is quarantined or frozen.
5. A durable audit record is written.
6. A PR-style remediation summary is prepared for manual review in V1.

The GitHub PR step is intentionally described as a prepared trail in V1. The current implementation is stubbed and does not open a real pull request.

## Prerequisites

- Windows PowerShell
- Docker Desktop
- Node.js
- Python 3.12+

No AWS credentials are required. The demo uses LocalStack credentials:

```powershell
$env:AWS_ACCESS_KEY_ID='test'
$env:AWS_SECRET_ACCESS_KEY='test'
$env:AWS_DEFAULT_REGION='us-east-1'
$env:CDK_DEFAULT_ACCOUNT='000000000000'
$env:CDK_DEFAULT_REGION='us-east-1'
```

## 1. Install Dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r lambda\requirements.txt -r lambda\requirements-dev.txt

cd cdk
npm install
cd ..
```

## 2. Run Fast Unit Checks

```powershell
.\.venv\Scripts\python.exe -m ruff check lambda scripts tests
.\.venv\Scripts\python.exe -m pip_audit -r lambda\requirements.txt -r lambda\requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest tests/unit -q

cd cdk
npm audit --audit-level=high
npm run build
npm test -- --runInBand
cd ..
```

Expected result:

```text
static analysis passes
Python dependency audit reports no known vulnerabilities
npm high-severity audit gate passes
unit tests pass
CDK TypeScript build passes
CDK template assertions pass
```

## 3. Deploy the Local AWS Environment

```powershell
docker compose up -d

cd cdk
$env:AWS_ACCESS_KEY_ID='test'
$env:AWS_SECRET_ACCESS_KEY='test'
$env:AWS_DEFAULT_REGION='us-east-1'
$env:CDK_DEFAULT_ACCOUNT='000000000000'
$env:CDK_DEFAULT_REGION='us-east-1'
$env:AEGISFLOW_LOCALSTACK='1'
$env:NODE_PATH=(Resolve-Path '.\node_modules').Path

npx aws-cdk-local@3.0.4 bootstrap aws://000000000000/us-east-1
npx aws-cdk-local@3.0.4 deploy --all --require-approval never
cd ..
```

LocalStack mode keeps the workflow behavior intact while adjusting networking constructs that the emulator does not fully support.

## 4. Run Integration Checks

```powershell
.\.venv\Scripts\python.exe -m pytest tests/integration -q --timeout=30
```

The integration suite checks durable remediation state instead of relying on Express Step Functions polling:

- DynamoDB jail record is written.
- IAM deny-all policy is attached for identity playbooks.
- EC2 security groups are replaced for compute playbooks.
- Evidence collection status is recorded before enforcement is finalized.

## 5. Run the Independent Audit Script

After a local integration run, use the audit script to verify a remediated resource:

```powershell
.\.venv\Scripts\python.exe scripts\verify_remediation.py `
  --resource-arn "arn:aws:iam::000000000000:role/aegisflow-demo-victim" `
  --endpoint "http://localhost:4566"
```

Expected shape:

```text
============================================================
AegisFlow Remediation Audit - arn:aws:iam::<ACCOUNT_ID>:role/aegisflow-demo-victim
============================================================
PASS  DynamoDB status: COMPLETE
PASS  IAM Deny-All policy: present
PASS  Evidence collection: success

AUDIT PASSED
```

Use `<ACCOUNT_ID>` in public screenshots or writeups. Do not publish real account IDs, credentials, CloudTrail records, or resource names from a personal AWS account.

## Demo Narrative

For a hiring manager or technical reviewer, the short version is:

> Aegis-Flow receives a high-severity GuardDuty-style finding, validates the target, collects evidence first, applies the matching remediation playbook, and records a verifiable audit trail. V1 proves the workflow locally with LocalStack and moto while keeping real AWS account details out of the public repo.

## Cleanup

```powershell
docker compose down
```
