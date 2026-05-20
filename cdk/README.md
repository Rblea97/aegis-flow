# Aegis-Flow CDK

This directory contains the AWS CDK TypeScript app for Aegis-Flow.

## Stacks

- `AegisFlowFoundationStack`: VPC, quarantine security group, S3 forensics bucket, DynamoDB jail table, and IAM roles.
- `AegisFlowPipelineStack`: Lambda remediator, Step Functions Express workflow, EventBridge GuardDuty rule, SNS topic, and logs.

## Production-like Synth

```powershell
npm install
npx cdk synth
```

Default synthesis preserves the spec-compliant architecture:

- Step Functions `EXPRESS`
- private subnets with egress
- one NAT gateway

For disposable real-account validation, set a short unique suffix before synth/deploy:

```powershell
$env:AEGISFLOW_NAME_SUFFIX='live-YYYYMMDD-shortid'
npx cdk deploy AegisFlowFoundationStack AegisFlowPipelineStack --require-approval never
```

The suffix is applied only to collision-prone physical names. Leave it unset for the default portfolio/demo names.

## LocalStack Deploy

LocalStack cannot reliably emulate the NAT gateway path, so local deployments use the explicit compatibility flag:

```powershell
$env:AWS_ACCESS_KEY_ID='test'
$env:AWS_SECRET_ACCESS_KEY='test'
$env:AWS_DEFAULT_REGION='us-east-1'
$env:CDK_DEFAULT_ACCOUNT='000000000000'
$env:CDK_DEFAULT_REGION='us-east-1'
$env:AEGISFLOW_LOCALSTACK='1'
$env:NODE_PATH=(Resolve-Path '.\node_modules').Path

npx aws-cdk-local@3.0.4 bootstrap aws://000000000000/us-east-1
npx aws-cdk-local@3.0.4 deploy --all --require-approval never
```

## Tests

```powershell
npm test -- --runInBand
```

The Jest tests assert the synthesized architecture: Express workflow, strict GuardDuty EventBridge routing, expected Lambda environment, DynamoDB jail table, and quarantine security group behavior.
