#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AegisFlowFoundationStack } from '../lib/foundation-stack';
import { AegisFlowPipelineStack } from '../lib/pipeline-stack';

const app = new cdk.App();

const foundation = new AegisFlowFoundationStack(app, 'AegisFlowFoundationStack', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
});

new AegisFlowPipelineStack(app, 'AegisFlowPipelineStack', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
  foundationStack: foundation,
});
