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

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // VPC: Lambda lives in private subnets; flow logs to S3
    this.vpc = new ec2.Vpc(this, 'AegisVpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
      maxAzs: 2,
      natGateways: 1,
      subnetConfiguration: [
        { name: 'Public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        { name: 'Private', subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS, cidrMask: 24 },
      ],
    });

    const flowLogsBucket = new s3.Bucket(this, 'FlowLogsBucket', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });
    this.vpc.addFlowLog('VpcFlowLog', {
      destination: ec2.FlowLogDestination.toS3(flowLogsBucket),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    // QuarantineSG: zero ingress + zero egress = deny all
    this.quarantineSg = new ec2.SecurityGroup(this, 'QuarantineSG', {
      vpc: this.vpc,
      description: 'AegisFlow quarantine — deny all traffic',
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
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    new cdk.CfnOutput(this, 'ActiveJailsTableName', { value: this.activeJailsTable.tableName });
  }
}
