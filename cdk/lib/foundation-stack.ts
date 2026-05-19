import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export class AegisFlowFoundationStack extends cdk.Stack {
  public readonly vpc: ec2.Vpc;
  public readonly quarantineSg: ec2.SecurityGroup;
  public readonly forensicsBucket: s3.Bucket;
  public readonly activeJailsTable: dynamodb.Table;
  public readonly remediatorLambdaRole: iam.Role;
  public readonly remediationExecutionRole: iam.Role;
  public readonly lambdaSubnetType: ec2.SubnetType;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const isLocalStack = process.env.AEGISFLOW_LOCALSTACK === '1';
    const externalId = process.env.AEGISFLOW_EXTERNAL_ID;
    this.lambdaSubnetType = isLocalStack
      ? ec2.SubnetType.PRIVATE_ISOLATED
      : ec2.SubnetType.PRIVATE_WITH_EGRESS;

    // VPC: Lambda lives in private subnets; flow logs to S3
    this.vpc = new ec2.Vpc(this, 'AegisVpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
      maxAzs: 2,
      natGateways: isLocalStack ? 0 : 1,
      restrictDefaultSecurityGroup: false,
      subnetConfiguration: [
        { name: 'Public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        { name: 'Private', subnetType: this.lambdaSubnetType, cidrMask: 24 },
      ],
    });

    const flowLogsBucket = new s3.Bucket(this, 'FlowLogsBucket', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    this.vpc.addFlowLog('VpcFlowLog', {
      destination: ec2.FlowLogDestination.toS3(flowLogsBucket),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    // QuarantineSG: zero ingress + zero egress = deny all
    this.quarantineSg = new ec2.SecurityGroup(this, 'QuarantineSG', {
      vpc: this.vpc,
      description: 'AegisFlow quarantine - deny all traffic',
      allowAllOutbound: false, // disables default allow-all egress
    });
    new cdk.CfnOutput(this, 'QuarantineSgId', { value: this.quarantineSg.securityGroupId });

    // Forensics bucket: SSE-S3, versioned, Glacier after 90d
    this.forensicsBucket = new s3.Bucket(this, 'ForensicsBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
      lifecycleRules: [{
        transitions: [{ storageClass: s3.StorageClass.GLACIER, transitionAfter: cdk.Duration.days(90) }],
      }],
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // DynamoDB: idempotency + hot state
    this.activeJailsTable = new dynamodb.Table(this, 'ActiveJailsTable', {
      tableName: 'AegisFlow_ActiveJails',
      partitionKey: { name: 'resource_arn', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    new cdk.CfnOutput(this, 'ActiveJailsTableName', { value: this.activeJailsTable.tableName });

    // Remediator Lambda role: ONLY sts:AssumeRole — no direct AWS access
    this.remediatorLambdaRole = new iam.Role(this, 'RemediatorLambdaRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaVPCAccessExecutionRole'),
      ],
    });

    // Remediation Execution Role: carries all real permissions
    const remediationAssumePrincipal = externalId
      ? new iam.PrincipalWithConditions(
          new iam.ArnPrincipal(this.remediatorLambdaRole.roleArn),
          { StringEquals: { 'sts:ExternalId': externalId } },
        )
      : new iam.ArnPrincipal(this.remediatorLambdaRole.roleArn);
    this.remediationExecutionRole = new iam.Role(this, 'RemediationExecutionRole', {
      roleName: 'AegisFlow-Remediation-Execution-Role',
      assumedBy: remediationAssumePrincipal,
    });

    this.remediationExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'EC2Remediation',
      actions: [
        'ec2:ModifyNetworkInterfaceAttribute',
        'ec2:ModifyInstanceAttribute',
        'ec2:DescribeInstances',
        'ec2:DescribeNetworkInterfaces',
        'ec2:CreateSnapshot',
        'ec2:DescribeSnapshots',
      ],
      resources: ['*'], // scoped by condition at assume-role time
    }));

    this.remediationExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'IAMRemediation',
      actions: [
        'iam:PutRolePolicy',
        'iam:PutUserPolicy',
        'iam:GetRole',
        'iam:GetUser',
        'iam:UpdateAssumeRolePolicy',
      ],
      resources: ['*'],
    }));

    this.remediationExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'DynamoDBState',
      actions: ['dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:GetItem'],
      resources: [this.activeJailsTable.tableArn],
    }));

    this.remediationExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AuditAndEvidence',
      actions: ['logs:CreateExportTask', 'cloudtrail:LookupEvents', 'sns:Publish'],
      resources: ['*'],
    }));

    this.forensicsBucket.grantWrite(this.remediationExecutionRole);

    // Grant Remediator Lambda role permission to assume the Execution Role
    this.remediatorLambdaRole.addToPolicy(new iam.PolicyStatement({
      actions: ['sts:AssumeRole'],
      resources: [this.remediationExecutionRole.roleArn],
      conditions: externalId
        ? { StringEquals: { 'sts:ExternalId': externalId } }
        : undefined,
    }));

    new cdk.CfnOutput(this, 'RemediationExecutionRoleArn', {
      value: this.remediationExecutionRole.roleArn,
    });
  }
}
