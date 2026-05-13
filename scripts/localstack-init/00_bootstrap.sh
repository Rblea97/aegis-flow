#!/bin/bash
set -e
ENDPOINT=http://localhost:4566
REGION=us-east-1

echo "==> Creating DynamoDB table"
aws --endpoint-url=$ENDPOINT dynamodb create-table \
  --table-name AegisFlow_ActiveJails \
  --attribute-definitions AttributeName=resource_arn,AttributeType=S \
  --key-schema AttributeName=resource_arn,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region $REGION || true

echo "==> Creating S3 forensics bucket"
aws --endpoint-url=$ENDPOINT s3 mb s3://aegisflow-forensics-test --region $REGION || true

echo "==> Creating VPC + SecurityGroups"
VPC_ID=$(aws --endpoint-url=$ENDPOINT ec2 create-vpc --cidr-block 10.0.0.0/16 \
  --query 'Vpc.VpcId' --output text --region $REGION)
SUBNET_ID=$(aws --endpoint-url=$ENDPOINT ec2 create-subnet \
  --vpc-id "$VPC_ID" --cidr-block 10.0.1.0/24 \
  --query 'Subnet.SubnetId' --output text --region $REGION)
WEB_SG_ID=$(aws --endpoint-url=$ENDPOINT ec2 create-security-group \
  --group-name WebTier-SG --description "Web tier" --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text --region $REGION)
QUARANTINE_SG_ID=$(aws --endpoint-url=$ENDPOINT ec2 create-security-group \
  --group-name Quarantine-SG --description "AegisFlow quarantine — deny all" --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text --region $REGION)

echo "QUARANTINE_SG_ID=$QUARANTINE_SG_ID" > /tmp/aegisflow-env
echo "WEB_SG_ID=$WEB_SG_ID" >> /tmp/aegisflow-env
echo "SUBNET_ID=$SUBNET_ID" >> /tmp/aegisflow-env
echo "VPC_ID=$VPC_ID" >> /tmp/aegisflow-env

echo "==> LocalStack bootstrap complete"
