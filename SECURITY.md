# Security Policy

## Supported Versions

This is a security automation demonstration project. It is not a production service and has no versioned releases.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please open a GitHub Issue or email rblea97@gmail.com. Do not include sensitive details (credentials, account IDs, exploit payloads) in public issues.

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
