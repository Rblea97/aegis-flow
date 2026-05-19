import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';

// Explicit .ts requires keep Jest from loading stale generated .js files.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { AegisFlowFoundationStack } = require('../lib/foundation-stack.ts');
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { AegisFlowPipelineStack } = require('../lib/pipeline-stack.ts');

function synthStacks(localstack = false, externalId?: string) {
  const previousLocalstack = process.env.AEGISFLOW_LOCALSTACK;
  const previousExternalId = process.env.AEGISFLOW_EXTERNAL_ID;
  if (localstack) {
    process.env.AEGISFLOW_LOCALSTACK = '1';
  } else {
    delete process.env.AEGISFLOW_LOCALSTACK;
  }
  if (externalId !== undefined) {
    process.env.AEGISFLOW_EXTERNAL_ID = externalId;
  } else {
    delete process.env.AEGISFLOW_EXTERNAL_ID;
  }

  const app = new cdk.App();
  const foundation = new AegisFlowFoundationStack(app, 'AegisFlowFoundationStack', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  const pipeline = new AegisFlowPipelineStack(app, 'AegisFlowPipelineStack', {
    env: { account: '123456789012', region: 'us-east-1' },
    foundationStack: foundation,
  });

  if (previousLocalstack === undefined) {
    delete process.env.AEGISFLOW_LOCALSTACK;
  } else {
    process.env.AEGISFLOW_LOCALSTACK = previousLocalstack;
  }
  if (previousExternalId === undefined) {
    delete process.env.AEGISFLOW_EXTERNAL_ID;
  } else {
    process.env.AEGISFLOW_EXTERNAL_ID = previousExternalId;
  }

  return {
    foundationTemplate: Template.fromStack(foundation),
    pipelineTemplate: Template.fromStack(pipeline),
  };
}

test('foundation stack preserves production network and jail store requirements', () => {
  const { foundationTemplate } = synthStacks();

  foundationTemplate.resourceCountIs('AWS::EC2::NatGateway', 1);
  foundationTemplate.hasResourceProperties('AWS::DynamoDB::Table', {
    TableName: 'AegisFlow_ActiveJails',
    KeySchema: [{ AttributeName: 'resource_arn', KeyType: 'HASH' }],
    BillingMode: 'PAY_PER_REQUEST',
    PointInTimeRecoverySpecification: {
      PointInTimeRecoveryEnabled: true,
    },
    TimeToLiveSpecification: {
      AttributeName: 'ttl',
      Enabled: true,
    },
  });
  const securityGroups = foundationTemplate.findResources('AWS::EC2::SecurityGroup', {
    Properties: { GroupDescription: 'AegisFlow quarantine - deny all traffic' },
  });
  const quarantineSecurityGroup = Object.values(securityGroups)[0] as {
    Properties: { SecurityGroupEgress?: Array<Record<string, string>> };
  };
  expect(quarantineSecurityGroup).toBeDefined();
  expect(quarantineSecurityGroup.Properties.SecurityGroupEgress ?? []).not.toContainEqual(
    expect.objectContaining({ CidrIp: '0.0.0.0/0' }),
  );
  foundationTemplate.hasResourceProperties('AWS::S3::Bucket', {
    VersioningConfiguration: { Status: 'Enabled' },
    BucketEncryption: {
      ServerSideEncryptionConfiguration: [
        { ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } },
      ],
    },
  });
});

test('pipeline stack uses express Step Functions and strict GuardDuty routing', () => {
  const { pipelineTemplate } = synthStacks();

  pipelineTemplate.hasResourceProperties('AWS::StepFunctions::StateMachine', {
    StateMachineType: 'EXPRESS',
    StateMachineName: 'AegisFlow-Remediator',
  });
  pipelineTemplate.hasResourceProperties('AWS::Events::Rule', {
    EventPattern: {
      source: ['aws.guardduty'],
      'detail-type': ['GuardDuty Finding'],
      detail: {
        severity: [{ numeric: ['>=', 7] }],
        type: [
          { prefix: 'Impact:EC2/CryptoMining' },
          { prefix: 'UnauthorizedAccess:IAMUser/ConsoleLoginSuccess' },
          { prefix: 'PrivilegeEscalation:IAMUser/AdministrativePermissions' },
        ],
      },
    },
  });
  pipelineTemplate.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'AegisFlow-Remediator',
    Runtime: 'python3.12',
    Environment: {
      Variables: Match.objectLike({
        ACTIVE_JAILS_TABLE: Match.anyValue(),
        FORENSICS_BUCKET: Match.anyValue(),
        QUARANTINE_SG_ID: Match.anyValue(),
        SNS_ALERT_TOPIC_ARN: Match.anyValue(),
      }),
    },
  });
});

test('configured external id is passed to Lambda and required by execution role trust', () => {
  const { foundationTemplate, pipelineTemplate } = synthStacks(false, 'aegisflow-release-polish');

  pipelineTemplate.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'AegisFlow-Remediator',
    Environment: {
      Variables: Match.objectLike({
        EXTERNAL_ID: 'aegisflow-release-polish',
      }),
    },
  });

  foundationTemplate.hasResourceProperties('AWS::IAM::Role', {
    RoleName: 'AegisFlow-Remediation-Execution-Role',
    AssumeRolePolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Action: 'sts:AssumeRole',
          Condition: {
            StringEquals: {
              'sts:ExternalId': 'aegisflow-release-polish',
            },
          },
        }),
      ]),
    },
  });
});

test('localstack mode preserves the express workflow contract', () => {
  const { pipelineTemplate } = synthStacks(true);

  pipelineTemplate.hasResourceProperties('AWS::StepFunctions::StateMachine', {
    StateMachineType: 'EXPRESS',
  });
});
