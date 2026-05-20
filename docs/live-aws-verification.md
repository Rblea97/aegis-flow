# Live AWS Verification Evidence

This page records the sanitized result of a real AWS E2E verification run. It intentionally omits raw account IDs, ARNs, bucket names, credentials, tokens, CloudTrail records, request IDs, and sensitive resource identifiers.

## Run Context

| Field | Sanitized value |
|---|---|
| Date | 2026-05-20 |
| AWS account | `<ACCOUNT_ID>` |
| AWS profile | `<AWS_PROFILE>` |
| Region | `<REGION>` |
| Live-run suffix | `live-20260520-cx01` |
| Evidence storage | Raw evidence captured under ignored `.tmp/live-aws-evidence/` only |
| Redaction policy | Public docs use placeholders for account, profile, region, ARNs, buckets, resources, timestamps, and request IDs |

## Result Summary

The live E2E run completed the disposable EC2 remediation path:

- CDK deployed the foundation and pipeline stacks with `AEGISFLOW_NAME_SUFFIX`.
- A disposable IAM role, instance profile, security group, EC2 instance, and EBS volume were created for the test.
- A GuardDuty-style `Impact:EC2/CryptoMining` event started the Step Functions workflow.
- Lambda validated the finding, acquired the DynamoDB lock, collected S3 evidence metadata, quarantined the EC2 target, froze the disposable instance role, and wrote the final audit record.
- `scripts/verify_remediation.py` independently audited the live remediated resource.
- A duplicate finding attempt kept exactly one DynamoDB record for the remediated resource.
- Cleanup was verified for live-created stacks, disposable resources, evidence snapshots, S3 buckets, and tags.

Two cloud-only issues were found and fixed before the successful retry:

- Fixed physical resource names could collide with pre-existing real-account resources. `AEGISFLOW_NAME_SUFFIX` now namespaces collision-prone names.
- The remediation execution role needed `iam:GetInstanceProfile` to freeze an EC2 instance role after quarantine.

## Commands Run

Commands are shown with placeholders. Raw outputs were captured only in ignored local evidence files.

```powershell
aws --version
aws configure get region
aws sts get-caller-identity --region <REGION>
aws cloudformation list-stacks --region <REGION> --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE
aws resourcegroupstaggingapi get-resources --region <REGION> --tag-filters Key=Project,Values=AegisFlow

$env:AEGISFLOW_NAME_SUFFIX='live-20260520-cx01'
cd cdk
npx cdk deploy AegisFlowFoundationStack AegisFlowPipelineStack `
  --require-approval never `
  --outputs-file '..\.tmp\live-aws-evidence\cdk-outputs-full-e2e.raw.json'
cd ..

aws iam create-role --role-name <ROLE_NAME> --assume-role-policy-document file://<POLICY_FILE> --tags file://<TAGS_FILE> --region <REGION>
aws iam create-instance-profile --instance-profile-name <ROLE_NAME> --tags file://<TAGS_FILE> --region <REGION>
aws iam add-role-to-instance-profile --instance-profile-name <ROLE_NAME> --role-name <ROLE_NAME> --region <REGION>
aws ec2 create-security-group --group-name <RESOURCE_NAME> --vpc-id <RESOURCE_ID> --region <REGION>
aws ec2 run-instances --image-id <RESOURCE_ID> --instance-type t3.nano --subnet-id <RESOURCE_ID> --security-group-ids <RESOURCE_ID> --iam-instance-profile Name=<ROLE_NAME> --region <REGION>
aws ec2 wait instance-running --instance-ids <RESOURCE_ID> --region <REGION>

aws stepfunctions start-execution --state-machine-arn <STATE_MACHINE_ARN> --input file://<FINDING_FILE> --region <REGION>
aws dynamodb get-item --table-name <TABLE_NAME> --key <RESOURCE_KEY_JSON> --region <REGION>
aws s3api head-object --bucket <BUCKET_NAME> --key <EVIDENCE_KEY> --region <REGION>
aws iam list-role-policies --role-name <ROLE_NAME> --region <REGION>
aws ec2 describe-instances --instance-ids <RESOURCE_ID> --region <REGION>
.\.venv\Scripts\python.exe scripts\verify_remediation.py --resource-arn <RESOURCE_ARN> --quarantine-sg-id <RESOURCE_ID> --table-name <TABLE_NAME>

aws stepfunctions start-execution --state-machine-arn <STATE_MACHINE_ARN> --input file://<DUPLICATE_FINDING_FILE> --region <REGION>
aws dynamodb scan --table-name <TABLE_NAME> --filter-expression 'resource_arn = :r' --expression-attribute-values <RESOURCE_VALUE_JSON> --region <REGION>

aws ec2 terminate-instances --instance-ids <RESOURCE_ID> <RESOURCE_ID> --region <REGION>
aws ec2 wait instance-terminated --instance-ids <RESOURCE_ID> <RESOURCE_ID> --region <REGION>
aws ec2 delete-snapshot --snapshot-id <RESOURCE_ID> --region <REGION>
aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name AegisFlow-Deny-All --region <REGION>
aws iam remove-role-from-instance-profile --instance-profile-name <ROLE_NAME> --role-name <ROLE_NAME> --region <REGION>
aws iam delete-instance-profile --instance-profile-name <ROLE_NAME> --region <REGION>
aws iam delete-role --role-name <ROLE_NAME> --region <REGION>
aws ec2 delete-security-group --group-id <RESOURCE_ID> --region <REGION>
aws s3api delete-objects --bucket <BUCKET_NAME> --delete file://<DELETE_PAYLOAD> --region <REGION>
aws s3api delete-bucket --bucket <BUCKET_NAME> --region <REGION>
cd cdk
npx cdk destroy AegisFlowPipelineStack AegisFlowFoundationStack --force
cd ..
aws cloudformation wait stack-delete-complete --stack-name AegisFlowPipelineStack --region <REGION>
aws cloudformation wait stack-delete-complete --stack-name AegisFlowFoundationStack --region <REGION>
aws resourcegroupstaggingapi get-resources --region <REGION> --tag-filters Key=Project,Values=AegisFlow
```

## Sanitized Evidence Matrix

| Evidence item | Sanitized result | Source command/tool | Notes |
|---|---|---|---|
| AWS identity preflight | PASS: identity confirmed for `<ACCOUNT_ID>` in `<REGION>` | AWS CLI `sts get-caller-identity` | Raw account ID and ARN omitted |
| Bootstrap/deploy | PASS: suffix-scoped foundation and pipeline stacks deployed | CDK CLI deploy | `AEGISFLOW_NAME_SUFFIX=live-20260520-cx01` avoided fixed-name collisions |
| Workflow execution | PASS: Step Functions execution wrote DynamoDB `COMPLETE` | AWS Step Functions + DynamoDB CLI | Express execution was verified through durable state |
| Lambda/remediation result | PASS: independent Boto3 audit passed | `scripts\verify_remediation.py` | Verified live resource post-state |
| DynamoDB audit | PASS: jail record status `COMPLETE` | AWS CLI `dynamodb get-item` | Raw resource ARN omitted |
| S3 evidence | PASS: evidence status `success`; metadata check found one evidence object | AWS CLI `s3api head-object` | Object contents were not read or published |
| IAM freeze | PASS: disposable instance role had `AegisFlow-Deny-All` | AWS CLI `iam list-role-policies` | Disposable role only |
| EC2 quarantine | PASS: disposable EC2 target had only the quarantine security group | AWS CLI `ec2 describe-instances` | Disposable instance only |
| Duplicate finding | PASS: duplicate start left exactly one DynamoDB record | AWS CLI Step Functions + DynamoDB scan | Confirms lock/idempotency behavior |
| Cleanup | PASS: stacks absent, no non-terminated live-test instances, snapshots gone, IAM fixtures absent, no live-test volumes, `Project=AegisFlow` tagged resource count `0` | CDK CLI + AWS CLI | Terminated instance records were untagged after termination |

## Verification Log

| Check | Command/tool | Scope | Result | Evidence | Notes |
|---|---|---|---|---|---|
| Format | Not applicable | Documentation and CDK changes | UNVERIFIED | No Markdown formatter configured | TypeScript build was run |
| Lint/static analysis | `ruff check lambda scripts tests` | Python source, scripts, tests | PASS | `All checks passed!` | Local interpreter was Python 3.14.4; CI uses Python 3.12 |
| Python dependency scan | `pip-audit -r lambda\requirements.txt -r lambda\requirements-dev.txt` | Python requirements | PASS | No known vulnerabilities found | Local run |
| Python unit tests | `pytest tests\unit -q` | Unit tests | PASS | `19 passed` | Local run |
| CDK dependency scan | `npm audit --audit-level=high` | CDK dependencies | PASS | Exit 0 with one documented moderate advisory | High severity gate passed |
| CDK build | `npm run build` | CDK TypeScript app | PASS | TypeScript build exited 0 | Local run |
| CDK tests | `npm test -- --runInBand` | CDK Jest tests | PASS | `5 passed` | Includes suffix and IAM permission assertions |
| LocalStack integration | LocalStack CDK deploy plus `pytest tests\integration -q --timeout=30` | Local AWS emulation | PASS | `4 passed` | Docker socket was mounted for LocalStack Lambda emulation |
| Independent local audit | `scripts\verify_remediation.py --endpoint http://localhost:4566` | LocalStack DynamoDB/IAM evidence | PASS | Audit script reported `AUDIT PASSED` | Fake account data only |
| Live AWS preflight | AWS CLI | Target account/region | PASS | Identity confirmed for `<ACCOUNT_ID>` in `<REGION>` | Raw identity omitted |
| Live AWS deployment | CDK CLI | Foundation and pipeline stacks | PASS | Both stacks deployed with suffix | Initial fixed-name collision was fixed before final retry |
| Live AWS workflow | Step Functions/Lambda | Disposable EC2 finding | PASS | DynamoDB status `COMPLETE` | First retry exposed missing `iam:GetInstanceProfile`; fixed before final retry |
| Live AWS cleanup | CDK CLI and AWS CLI | Live-created resources | PASS | Stacks absent and `Project=AegisFlow` tagged resource count `0` | Stack-owned buckets were emptied/deleted narrowly |
| Secret scan | Repository scanner/manual search | Tracked files | PASS | See final verification notes | No real credentials or account IDs intentionally added |
| Documentation review | Manual diff review | README, DEMO, ARCHITECTURE, SECURITY, live evidence docs | PASS | Sanitized placeholders only | No raw CloudTrail or S3 object contents |
| GitHub CI | GitHub Actions | Branch/PR checks | UNVERIFIED | No PR/check run was created in this session | Existing `master` branch is protected |

## Limitations

- This is a disposable portfolio validation, not proof of production readiness.
- The live run used a GuardDuty-style fixture event instead of a GuardDuty-generated finding.
- Public documentation includes evidence metadata and state checks only; raw CloudTrail records and S3 object contents are intentionally omitted.
- GitHub Actions CI is `UNVERIFIED` until this branch is pushed and a PR/check run exists.
