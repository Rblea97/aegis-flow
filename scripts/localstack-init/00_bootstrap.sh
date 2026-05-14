#!/bin/bash
set -e
ENDPOINT=http://localhost:4566
REGION=us-east-1

echo "==> Creating DynamoDB table"
echo "Skipping DynamoDB table creation; CDK owns AegisFlow_ActiveJails."

echo "==> Creating S3 forensics bucket"
echo "Skipping forensics bucket creation; CDK owns the forensics bucket."

echo "==> Creating VPC + SecurityGroups"
echo "Skipping VPC and security group creation; CDK owns infrastructure."

echo "==> LocalStack bootstrap complete"
