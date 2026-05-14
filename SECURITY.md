# Security Policy

## Supported Versions

This is a security automation demonstration project. It is not a production service and has no versioned releases.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please open a GitHub Issue or email rblea97@gmail.com. Do not include sensitive details (credentials, account IDs, exploit payloads) in public issues.

Response time: best effort within 7 days.

## Security Design Notes

This project demonstrates defense-in-depth AWS security automation:

- **Role separation** — The Lambda execution role (`RemediatorLambdaRole`) has no direct AWS permissions; all real API calls go through an assumed `RemediationExecutionRole` via STS.
- **Confused-deputy prevention** — The execution role's trust policy includes an `aws:SourceArn` condition scoped to the specific Lambda function ARN.
- **Idempotent locking** — DynamoDB conditional writes prevent duplicate remediation from concurrent findings targeting the same resource.
- **Evidence-before-enforcement** — CloudTrail evidence is collected to S3 before any network or identity enforcement action.
- **Least-privilege networking** — Lambda runs in private subnets with egress only; quarantine security group denies all inbound and outbound traffic.
