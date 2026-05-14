# Aegis-Flow

[![CI](https://github.com/rblea97/aegis-flow/actions/workflows/ci.yml/badge.svg)](https://github.com/rblea97/aegis-flow/actions/workflows/ci.yml)

Aegis-Flow is a local-first AWS security automation lab that detects GuardDuty-style findings, collects evidence, quarantines compromised resources, freezes identity access, and writes an auditable remediation record.

## Tech Stack

![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![AWS CDK](https://img.shields.io/badge/AWS_CDK-TypeScript-FF9900?logo=amazon-aws&logoColor=white)
![Step Functions](https://img.shields.io/badge/Step_Functions-Express-FF9900?logo=amazon-aws&logoColor=white)
![GuardDuty + EventBridge](https://img.shields.io/badge/GuardDuty%2BEventBridge-finding--driven-FF9900?logo=amazon-aws&logoColor=white)
![DynamoDB](https://img.shields.io/badge/DynamoDB-idempotency-4053D6?logo=amazon-dynamodb&logoColor=white)
![S3](https://img.shields.io/badge/S3-forensics-569A31?logo=amazon-s3&logoColor=white)
![LocalStack](https://img.shields.io/badge/LocalStack-3-1F8AC0?logo=docker&logoColor=white)
![pytest + moto](https://img.shields.io/badge/pytest%2Fmoto-16%20tests-0A9EDC?logo=pytest&logoColor=white)

| Technology | Why |
|---|---|
| Python 3.12 Lambda | async-friendly, rich boto3 ecosystem |
| AWS CDK (TypeScript) | repeatable infra-as-code with type safety |
| Step Functions Express | built-in retry, error routing, audit trail |
| GuardDuty + EventBridge | finding-driven routing without polling |
| DynamoDB | conditional writes prevent duplicate remediation |
| S3 | versioned evidence bucket with Glacier lifecycle |
| LocalStack 3 | full local AWS emulation without an AWS account |
| pytest + moto | in-process mocks, no real AWS needed for unit tests |

## Key Features

- A compromised EC2 instance is network-isolated within one state-machine execution — no manual firewall rule changes required.
- A compromised IAM user or role is locked with a Deny-All policy before any further API calls can propagate the breach.
- All evidence (CloudTrail events, instance metadata) is captured to S3 before enforcement — preserving the attack chain for forensics.
- Every remediation attempt is idempotent — duplicate GuardDuty findings for the same resource produce exactly one jail record.
- Post-remediation state is independently verified by a Boto3 audit script that exits non-zero on any gap.

## Quick Start

Prerequisites:

- Windows PowerShell
- Docker Desktop
- Node.js and npm
- Python 3.12+ or compatible local Python

Install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r lambda\requirements.txt -r lambda\requirements-dev.txt

cd cdk
npm install
cd ..
```

Run unit checks:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit -q
cd cdk
npm test -- --runInBand
cd ..
```

Run the LocalStack integration proof:

```powershell
docker compose down
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

.\.venv\Scripts\python.exe -m pytest tests/integration -q --timeout=30
```

Run the post-remediation audit:

```powershell
.\.venv\Scripts\python.exe scripts\verify_remediation.py `
  --resource-arn "<resource ARN from DynamoDB>" `
  --endpoint "http://localhost:4566" `
  --quarantine-sg-id "<QuarantineSgId from CDK output>" `
  --table-name "AegisFlow_ActiveJails"
```

Exit code `0` means the audit passed.

## Proof

16 unit tests pass against in-process moto mocks with no LocalStack or AWS account needed:

~~~text
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.0.3, pluggy-1.6.0
rootdir: C:\Users\Richie\Documents\Projects\Aegis-Flow
configfile: pytest.ini
collected 16 items

tests/unit/test_audit.py::test_write_audit_record_sets_complete PASSED   [  6%]
tests/unit/test_audit.py::test_write_failed_record_sets_error PASSED     [ 12%]
tests/unit/test_evidence.py::test_compute_evidence_returns_status_field PASSED [ 18%]
tests/unit/test_evidence.py::test_identity_evidence_returns_status_field PASSED [ 25%]
tests/unit/test_handler.py::test_handler_rejects_unknown_action PASSED   [ 31%]
tests/unit/test_handler.py::test_handler_validate_event_returns_context PASSED [ 37%]
tests/unit/test_identity.py::test_compute_attaches_deny_policy_to_instance_role PASSED [ 43%]
tests/unit/test_identity.py::test_identity_attaches_deny_and_revokes_sts PASSED [ 50%]
tests/unit/test_locker.py::test_acquire_lock_writes_locked_status PASSED [ 56%]
tests/unit/test_locker.py::test_acquire_lock_raises_on_duplicate PASSED  [ 62%]
tests/unit/test_network.py::test_compute_quarantine_swaps_sg PASSED      [ 68%]
tests/unit/test_network.py::test_identity_quarantine_is_noop PASSED      [ 75%]
tests/unit/test_validator.py::test_validate_cryptomining_returns_compute_context PASSED [ 81%]
tests/unit/test_validator.py::test_validate_console_login_returns_identity_context PASSED [ 87%]
tests/unit/test_validator.py::test_validate_rejects_invalid_arn PASSED   [ 93%]
tests/unit/test_validator.py::test_validate_rejects_unknown_finding_type PASSED [100%]

============================= 16 passed in 2.27s ==============================
~~~

Integration tests require LocalStack + `cdklocal deploy` — see Quick Start above.

### Live AWS execution (account 560904638100, us-west-1)

Step Functions Express state machine executed end-to-end against a real AWS account. IAM role `aegisflow-demo-victim` was targeted with a `PrivilegeEscalation:IAMUser/AdministrativePermissions` finding. All 7 states completed in 4.1 seconds:

~~~text
{
    "status": "SUCCEEDED",
    "billingDetails": {
        "billedMemoryUsedInMB": 64,
        "billedDurationInMilliseconds": 4100
    },
    "output": {
        "identityResult": {
            "Payload": {
                "action_taken": "deny_policy_attached_with_sts_revocation",
                "target": "arn:aws:iam::560904638100:role/aegisflow-demo-victim",
                "sts_sessions_revoked": true
            }
        },
        "evidenceResult": {
            "Payload": {
                "evidence_collection_status": "success",
                "evidence_s3_uris": [
                    "s3://aegisflowfoundationstack-forensicsbucket.../evidence/ghi789/cloudtrail-export.json"
                ]
            }
        }
    }
}
~~~

Post-execution audit confirmed:

~~~text
============================================================
AegisFlow Remediation Audit - arn:aws:iam::560904638100:role/aegisflow-demo-victim
============================================================
PASS DynamoDB status: COMPLETE
PASS IAM Deny-All policy: present
PASS Evidence collection: success

AUDIT PASSED
~~~

## Challenges and Solutions

- **LocalStack partial Express Step Functions support** — LocalStack 3 does not execute Express state machines end-to-end identically to real AWS. Integration tests verify correctness through durable post-state assertions (DynamoDB status, IAM policy presence, EC2 security group membership) rather than polling `DescribeExecution`. This matches the real definition of done: the audit trail in DynamoDB is the ground truth, not the execution response.

- **Conditional DynamoDB locking without transactions** — Two concurrent findings for the same resource must produce exactly one jail record. `AcquireLock` uses a `ConditionExpression` that fails if the partition key already exists, so the second execution exits via `AlreadyLocked` without applying any remediation action — no distributed transaction required.

- **CDK bootstrap ownership conflict with LocalStack init** — LocalStack's init script and CDK bootstrap both want to create foundational resources. The init script now creates only raw infrastructure (VPC, security groups, S3 bucket, DynamoDB table), while CDK owns IAM roles, Lambda, and Step Functions — making `cdklocal deploy` the single source of truth for the orchestration layer.

## Architecture

Aegis-Flow uses a two-stack CDK design: a Foundation stack for network, storage, state, and IAM roles, plus a Pipeline stack for Lambda, Step Functions, EventBridge, SNS, and logs. The remediation flow is documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Notes

- This repo currently demonstrates a terminal/API security automation lab, not a browser UI.
- Production AWS deployment via `cdk deploy --all` is the natural next step after LocalStack validation.
- LocalStack mode is for emulator compatibility only; production synth defaults to private subnets with egress and an Express state machine.

## License

MIT — see [LICENSE](LICENSE)
