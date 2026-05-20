# Security Policy

## Supported Versions

This is a security automation demonstration project. It is not a production service and has no versioned releases.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please open a GitHub Issue. Do not include sensitive details (credentials, account IDs, exploit payloads) in public issues.

Response time: best effort within 7 days.

## Security Design Notes

This project demonstrates defense-in-depth AWS security automation:

- **Role separation** — The Lambda execution role (`RemediatorLambdaRole`) keeps only Lambda runtime VPC/logging permissions plus `sts:AssumeRole`; remediation API calls go through an assumed `RemediationExecutionRole`.
- **Assume-role boundary** — The execution role only trusts the Lambda execution role. Deployments can set `AEGISFLOW_EXTERNAL_ID` to require a matching STS `ExternalId` on the assume-role call.
- **Idempotent locking** — DynamoDB conditional writes prevent duplicate remediation from concurrent findings targeting the same resource.
- **Evidence-before-enforcement** — CloudTrail evidence is collected to S3 before any network or identity enforcement action.
- **Least-privilege networking** — Lambda runs in private subnets with egress only; quarantine security group denies all inbound and outbound traffic.

## Constrained Development Gate

AI-generated code is not trusted by default. V1 changes are expected to pass:

- Ruff static analysis for Python code.
- TypeScript compilation and CDK template assertions.
- `pip-audit`, npm high-severity audit gates, Dependabot, and Dependency Review for dependency risk.
- CodeQL for GitHub-hosted semantic security analysis.
- Unit tests before merge, with LocalStack integration checks for release validation.

## Tracked Dependency Exceptions

| Dependency | Severity | Source | Current action |
| --- | --- | --- | --- |
| `brace-expansion` bundled under `aws-cdk-lib` | Moderate | GHSA-jxxr-4gwj-5jf2 | Accepted temporarily because `npm audit fix` cannot patch bundled dependencies inside `aws-cdk-lib@2.255.0`. Keep `npm audit --audit-level=high` as the blocking CI gate, monitor Dependabot for an upstream CDK release, and revisit before the next tagged release. |

## Live AWS Evidence Handling

Live verification output is treated as sensitive by default. Raw AWS CLI, CDK, CloudFormation, S3, DynamoDB, IAM, and Step Functions output must stay in ignored local evidence folders and must be sanitized before public documentation is updated.

The 2026-05-20 live verification run used disposable EC2 and IAM resources, suffix-scoped CDK physical names, and ignored local evidence files. Raw account IDs, ARNs, request IDs, S3 object contents, and CloudTrail event records were not added to public documentation. Cleanup was limited to live-created stacks, disposable EC2/IAM resources, evidence snapshots, stack-owned buckets, and tags created for the run.
