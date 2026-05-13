import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { AegisFlowFoundationStack } from './foundation-stack';

interface PipelineStackProps extends cdk.StackProps {
  foundationStack: AegisFlowFoundationStack;
}

export class AegisFlowPipelineStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: PipelineStackProps) {
    super(scope, id, props);

    const { vpc, quarantineSg, forensicsBucket, activeJailsTable,
            remediatorLambdaRole, remediationExecutionRole } = props.foundationStack;

    // SNS topic for security ops alerts
    const securityOpsTopic = new sns.Topic(this, 'SecurityOpsTopic', {
      topicName: 'aegisflow-security-ops',
    });

    // Remediator Lambda — single dispatcher for all state machine states
    const remediatorFn = new lambda.Function(this, 'AegisRemediatorFunction', {
      functionName: 'AegisFlow-Remediator',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'aegis_remediator.handler.handler',
      code: lambda.Code.fromAsset('../lambda'),
      role: remediatorLambdaRole,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      timeout: cdk.Duration.minutes(5),
      memorySize: 256,
      environment: {
        EXECUTION_ROLE_ARN: remediationExecutionRole.roleArn,
        ACTIVE_JAILS_TABLE: activeJailsTable.tableName,
        FORENSICS_BUCKET: forensicsBucket.bucketName,
        QUARANTINE_SG_ID: quarantineSg.securityGroupId,
        SNS_ALERT_TOPIC_ARN: securityOpsTopic.topicArn,
        // EXTERNAL_ID injected from Secrets Manager at deploy time (see README)
      },
      tracing: lambda.Tracing.ACTIVE,
    });

    // Helper: build a LambdaInvoke state with the action name stamped into payload
    const state = (id: string, action: string, resultPath: string) =>
      new tasks.LambdaInvoke(this, id, {
        lambdaFunction: remediatorFn,
        payload: sfn.TaskInput.fromObject({
          'action': action,
          'context.$': '$',
        }),
        resultPath,
        retryOnServiceExceptions: false,
      });

    // RemediationFailed state (terminal on error)
    const remediationFailed = new tasks.LambdaInvoke(this, 'RemediationFailed', {
      lambdaFunction: remediatorFn,
      payload: sfn.TaskInput.fromObject({
        'action': 'RemediationFailed',
        'context.$': '$',
      }),
      resultPath: '$.failedResult',
    }).next(new sfn.Fail(this, 'ExecutionFailed', {
      error: 'RemediationFailed',
      cause: 'States 4 or 5 threw an unexpected error — see DynamoDB for partial_actions_completed',
    }));

    // Happy-path states
    const validateEvent   = state('ValidateEvent',     'ValidateEvent',     '$.context');
    const acquireLock     = state('AcquireLock',       'AcquireLock',       '$.lockResult');
    const collectEvidence = state('CollectEvidence',   'CollectEvidence',   '$.evidenceResult');

    const quarantineNetwork = state('QuarantineNetwork', 'QuarantineNetwork', '$.networkResult');
    quarantineNetwork.addCatch(remediationFailed, {
      errors: ['States.ALL'],
      resultPath: '$.error',
    });
    quarantineNetwork.addRetry({ maxAttempts: 3, backoffRate: 2, interval: cdk.Duration.seconds(2) });

    const freezeIdentity = state('FreezeIdentity', 'FreezeIdentity', '$.identityResult');
    freezeIdentity.addCatch(remediationFailed, {
      errors: ['States.ALL'],
      resultPath: '$.error',
    });
    freezeIdentity.addRetry({ maxAttempts: 3, backoffRate: 2, interval: cdk.Duration.seconds(2) });

    const writeAuditRecord = state('WriteAuditRecord', 'WriteAuditRecord', '$.auditResult');
    const createGitHubPR   = state('CreateGitHubPR',   'CreateGitHubPR',   '$.prResult');

    const definition = validateEvent
      .next(acquireLock)
      .next(collectEvidence)
      .next(quarantineNetwork)
      .next(freezeIdentity)
      .next(writeAuditRecord)
      .next(createGitHubPR);

    const stateMachine = new sfn.StateMachine(this, 'AegisRemediatorStateMachine', {
      stateMachineName: 'AegisFlow-Remediator',
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      stateMachineType: sfn.StateMachineType.EXPRESS,
      tracingEnabled: true,
      logs: {
        destination: new logs.LogGroup(this, 'StateMachineLogs', {
          logGroupName: '/aegisflow/state-machine',
          removalPolicy: cdk.RemovalPolicy.DESTROY,
        }),
        level: sfn.LogLevel.ALL,
      },
    });

    // EventBridge rule: GuardDuty HIGH findings only
    const rule = new events.Rule(this, 'GuardDutyFindingRule', {
      eventPattern: {
        source: ['aws.guardduty'],
        detailType: ['GuardDuty Finding'],
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
    rule.addTarget(new targets.SfnStateMachine(stateMachine));

    new cdk.CfnOutput(this, 'StateMachineArn', { value: stateMachine.stateMachineArn });
  }
}
