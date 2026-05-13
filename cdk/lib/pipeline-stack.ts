import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { AegisFlowFoundationStack } from './foundation-stack';

interface PipelineStackProps extends cdk.StackProps {
  foundationStack: AegisFlowFoundationStack;
}

export class AegisFlowPipelineStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: PipelineStackProps) {
    super(scope, id, props);
    // Implemented in Task 4
  }
}
