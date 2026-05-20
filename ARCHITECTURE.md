# Aegis-Flow Architecture

## Overview

Aegis-Flow is a Zero Trust remediation workflow for GuardDuty-style findings. A high-severity finding is routed into an Express Step Functions workflow, where a Python Lambda validates the event, acquires a DynamoDB lock, collects evidence, applies quarantine controls, writes an audit record, and prepares a PR-style remediation summary for review.

## Component Model

```text
GuardDuty Finding
  -> EventBridge Rule
  -> Step Functions Express Workflow
  -> Aegis Remediator Lambda
  -> EC2 / IAM / DynamoDB / S3 / SNS
```

The project uses two CDK stacks:

- `AegisFlowFoundationStack`: VPC, quarantine security group, forensics bucket, active jail table, Lambda execution role, remediation execution role.
- `AegisFlowPipelineStack`: SNS topic, Lambda function, Step Functions workflow, EventBridge rule, workflow logs.

## Remediation Flow

The Step Functions workflow runs these states:

1. `ValidateEvent`
2. `AcquireLock`
3. `CollectEvidence`
4. `QuarantineNetwork`
5. `FreezeIdentity`
6. `WriteAuditRecord`
7. `CreateGitHubPR`

In V1, `CreateGitHubPR` prepares PR-style metadata and returns a structured result. It is intentionally stubbed until a real GitHub integration is added.

The workflow remains `EXPRESS` to match the design spec. Integration tests verify the workflow through durable state changes rather than polling Express execution details.

## Playbooks

`COMPUTE` findings target EC2 resources:

- Trigger: `Impact:EC2/CryptoMining`
- Enforcement: replace target network interface and instance security groups with the quarantine security group.
- Identity control: attach `AegisFlow-Deny-All` to the instance role.

`IDENTITY` findings target IAM principals:

- Triggers: `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`, `PrivilegeEscalation:IAMUser/AdministrativePermissions`
- Enforcement: attach `AegisFlow-Deny-All` to the user or role.
- Network quarantine is recorded as skipped because there is no EC2 target.

## State and Idempotency

DynamoDB table `AegisFlow_ActiveJails` is the active remediation ledger. The partition key is `resource_arn`. `AcquireLock` uses a conditional write so duplicate findings for the same resource do not create duplicate jail records.

## IAM Boundary

The Lambda execution role is deliberately narrow: it has Lambda runtime VPC/logging permissions and can assume the remediation execution role, but it does not receive direct EC2, IAM, DynamoDB, S3, or CloudTrail remediation permissions. All AWS remediation state changes happen through the assumed role. When `AEGISFLOW_EXTERNAL_ID` is configured at deploy time, CDK adds the matching `sts:ExternalId` condition to the execution role trust policy and the Lambda passes that value during `AssumeRole`.

## LocalStack Compatibility

The default CDK synthesis path is the production/spec path:

- Step Functions: Express
- Private subnets: private with egress
- NAT gateways: one

LocalStack has partial support for some EC2 networking features, so local deployment uses:

```powershell
$env:AEGISFLOW_LOCALSTACK='1'
```

This disables NAT gateway creation and uses isolated private subnets only for the emulator. It does not change the workflow type or remediation behavior.

## Verification

Verification is state-based:

- Unit tests use moto for in-process AWS mocks.
- Integration tests deploy CDK to LocalStack and assert DynamoDB, IAM, and EC2 post-state.
- `scripts/verify_remediation.py` independently audits the remediated resource using Boto3.

Live AWS verification evidence is tracked separately in [docs/live-aws-verification.md](docs/live-aws-verification.md). The 2026-05-20 live run verified the disposable EC2 path through deployment, Step Functions execution, Lambda remediation, DynamoDB audit state, S3 evidence metadata, IAM freeze behavior, EC2 quarantine, duplicate finding idempotency, and cleanup.

For real-account validation, set `AEGISFLOW_NAME_SUFFIX` to a short unique value. The suffix namespaces collision-prone physical names such as the DynamoDB table, remediation execution role, Lambda function, Lambda log group, Step Functions state machine, state machine log group, and SNS topic while preserving the default portfolio/demo names when the variable is unset.
