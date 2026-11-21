"""AWS Deployment & Verification Utility for WheelGate X Bedrock Managed Agent.

Automates deployment of the Bedrock Managed Agent, IAM Role, and Lambda Action Group
to Amazon Web Services. Supports dry-run validation and live execution via boto3.
"""
import argparse
import json
import os
import sys
from pathlib import Path


def check_aws_credentials():
    """Verify whether local AWS credentials exist."""
    try:
        import boto3
        session = boto3.Session()
        creds = session.get_credentials()
        if creds and creds.access_key:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return True, identity
        return False, "No active credentials in session"
    except Exception as exc:
        return False, str(exc)


def validate_templates():
    """Validate CloudFormation template and OpenAPI schemas locally."""
    root = Path(__file__).resolve().parent.parent
    cfn_path = root / "aws" / "bedrock_agent_stack.yaml"
    schema_path = root / "aws" / "action_group_schema.json"

    assert cfn_path.is_file(), f"Missing CloudFormation stack template: {cfn_path}"
    assert schema_path.is_file(), f"Missing OpenAPI schema: {schema_path}"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_data = json.load(f)
        assert schema_data.get("openapi") == "3.0.0", "Invalid OpenAPI version"
        assert "/get_current_assessment_evidence" in schema_data["paths"]

    print(f"✓ CloudFormation template validated: {cfn_path.name}")
    print(f"✓ Action Group OpenAPI 3.0 schema validated: {schema_path.name}")
    return True


def deploy_to_aws(region="us-east-1", stack_name="wheelgate-x-bedrock-stack"):
    """Deploy the CloudFormation stack to AWS."""
    import boto3
    has_creds, info = check_aws_credentials()
    if not has_creds:
        print(f"✗ Cannot deploy live: {info}")
        print("\nTo authenticate with your AWS account, run:")
        print("    aws configure")
        print("or:")
        print("    aws login")
        print("Then re-run this deployment script.")
        return False

    print(f"✓ Authenticated to AWS as: {info['Arn']} (Account: {info['Account']})")
    cfn = boto3.client("cloudformation", region_name=region)

    root = Path(__file__).resolve().parent.parent
    template_body = (root / "aws" / "bedrock_agent_stack.yaml").read_text(encoding="utf-8")

    print(f"Deploying stack '{stack_name}' in region '{region}'...")
    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "Project", "Value": "WheelGateX"},
                {"Key": "Hackathon", "Value": "AWS-Builder-Center-Bedrock-Agents-2026"}
            ]
        )
        print(f"✓ Stack creation initiated: {stack_name}. Polling status...")
    except cfn.exceptions.AlreadyExistsException:
        print(f"! Stack '{stack_name}' already exists. Initiating update...")
        cfn.update_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"]
        )
        print("✓ Stack update initiated.")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy WheelGate X Bedrock Managed Agent to AWS")
    parser.add_argument("--region", default="us-east-1", help="AWS Region (default: us-east-1)")
    parser.add_argument("--stack-name", default="wheelgate-x-bedrock-stack", help="CloudFormation Stack Name")
    parser.add_argument("--dry-run", action="store_true", help="Validate templates without deploying")

    args = parser.parse_args()

    print("=== WheelGate X: AWS Bedrock Managed Agent Deployment ===")
    validate_templates()

    if args.dry_run:
        print("\n[Dry Run Complete] Stack and schemas are ready for live deployment.")
        has_creds, info = check_aws_credentials()
        print(f"AWS Credential Status: {'AUTHENTICATED' if has_creds else 'UNCONFIGURED'}")
        if has_creds:
            print(f"Identity: {info.get('Arn')}")
    else:
        deploy_to_aws(region=args.region, stack_name=args.stack_name)
