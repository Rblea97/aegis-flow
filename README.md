# Aegis-Flow

Aegis-Flow is a local-first AWS security automation lab that detects GuardDuty-style findings, collects evidence, quarantines compromised resources, freezes identity access, and writes an auditable remediation record.

## Current Status

This project is verified as a LocalStack security lab. It is not a web demo; the proof is terminal/API based through CDK, Step Functions, Lambda, pytest, and a Boto3 audit script.

## Tech Stack

- AWS CDK with TypeScript: infrastructure definition and repeatable deployment.
- AWS Step Functions Express: ordered remediation workflow.
- Python 3.12 Lambda: remediation dispatcher and playbook logic.
- GuardDuty/EventBridge model: finding-driven routing.
- DynamoDB: idempotency and active remediation state.
- S3: forensic evidence destination.
- LocalStack: safe local AWS emulation for portfolio proof.
- pytest/moto/Boto3: unit, integration, and post-state verification.

## Key Features

- Detects high-severity GuardDuty-style CryptoMining and IAM findings.
- Collects evidence before enforcement.
- Quarantines EC2 resources by replacing security groups with a deny-all quarantine group.
- Freezes IAM users or roles with an `AegisFlow-Deny-All` inline policy.
- Records remediation status, evidence state, and timestamps in DynamoDB.
- Verifies post-remediation state with an automated Boto3 audit script.

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

## Challenges and Solutions

- LocalStack does not support every CDK-generated AWS path exactly like AWS. The production CDK defaults stay spec-compliant, while `AEGISFLOW_LOCALSTACK=1` disables only the NAT gateway path that LocalStack cannot emulate reliably.
- Express Step Functions executions are not polled with `DescribeExecution` in integration tests. Tests instead assert durable post-state in DynamoDB, IAM, and EC2, which matches the project definition of done.
- CDK and bootstrap ownership conflicted at first. LocalStack init now avoids creating resources that CDK owns, so stack deployment is the single source of infrastructure truth.

## Architecture

Aegis-Flow uses a two-stack CDK design: a Foundation stack for network, storage, state, and IAM roles, plus a Pipeline stack for Lambda, Step Functions, EventBridge, SNS, and logs. The remediation flow is documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Notes

- This repo currently demonstrates a terminal/API security automation lab, not a browser UI.
- Real AWS deployment has not been validated in this workspace.
- LocalStack mode is for emulator compatibility only; production synth defaults to private subnets with egress and an Express state machine.

## License

MIT — see [LICENSE](LICENSE)
