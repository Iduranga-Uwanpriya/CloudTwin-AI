"""
AWS Account management — connect, list, disconnect.
"""
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User, AwsAccount, ScanResult
from backend.app.auth import get_current_user

router = APIRouter(prefix="/aws-accounts", tags=["AWS Accounts"])
ROLE_ARN_PATTERN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:role\/[\w+=,.@\-_/]+$"
)


#  Schemas 

class ConnectAwsRequest(BaseModel):
    account_alias: str       # friendly name, e.g. "Production"
    role_arn: str             # arn:aws:iam::123456789012:role/CloudTwinReadOnly

    @field_validator("account_alias")
    @classmethod
    def validate_account_alias(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Account alias is required")
        return value

    @field_validator("role_arn")
    @classmethod
    def validate_role_arn(cls, value: str) -> str:
        value = value.strip()
        if not ROLE_ARN_PATTERN.match(value):
            raise ValueError(
                "Role ARN must be in format: arn:aws:iam::123456789012:role/RoleName"
            )
        return value


class AwsAccountResponse(BaseModel):
    id: str
    account_alias: str
    role_arn: str
    external_id: str
    aws_account_id: str | None
    is_active: bool
    last_scanned_at: str | None
    compliance_score: float | None = None


class OnboardingResponse(BaseModel):
    account: AwsAccountResponse
    cloudformation_template_url: str
    setup_instructions: list[str]


#  Endpoints 

@router.post("/connect", response_model=OnboardingResponse, status_code=201)
def connect_aws_account(
    body: ConnectAwsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Connect a new AWS account.
    Returns the external_id and CloudFormation template URL needed
    to create the read-only IAM role in the customer's account.
    """
    # Check duplicate (only among active accounts)
    existing = (
        db.query(AwsAccount)
        .filter(AwsAccount.user_id == current_user.id, AwsAccount.role_arn == body.role_arn, AwsAccount.is_active == True)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="This Role ARN is already connected")

    account = AwsAccount(
        user_id=current_user.id,
        account_alias=body.account_alias,
        role_arn=body.role_arn,
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    return OnboardingResponse(
        account=_to_response(account),
        cloudformation_template_url="/api/v1/aws-accounts/cloudformation-template",
        setup_instructions=[
            f"1. Download the CloudFormation template from the URL above.",
            f"2. Go to AWS Console -> CloudFormation -> Create Stack.",
            f"3. Upload the template and set ExternalId to: {account.external_id}",
            f"4. The stack creates a read-only IAM role that CloudTwin AI uses to scan your resources.",
            f"5. Once the stack is complete, click 'Scan Now' in the dashboard.",
        ],
    )


@router.get("/", response_model=list[AwsAccountResponse])
def list_aws_accounts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all connected AWS accounts for the current user."""
    accounts = (
        db.query(AwsAccount)
        .filter(AwsAccount.user_id == current_user.id)
        .order_by(AwsAccount.created_at.desc())
        .all()
    )
    responses = []
    for account in accounts:
        latest_scan = (
            db.query(ScanResult)
            .filter(ScanResult.aws_account_id == account.id)
            .order_by(ScanResult.created_at.desc())
            .first()
        )
        responses.append(_to_response(account, latest_scan.overall_score if latest_scan else None))
    return responses


@router.delete("/{account_id}")
def disconnect_aws_account(
    account_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disconnect and remove an AWS account."""
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    db.delete(account)
    db.commit()
    return {"status": "disconnected", "account_id": account_id}


@router.get("/cloudformation-template")
def get_cloudformation_template():
    """
    Returns a CloudFormation template that customers deploy in their
    AWS account to create the read-only IAM role.
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "CloudTwin AI - Read-Only Cross-Account IAM Role",
        "Parameters": {
            "ExternalId": {
                "Type": "String",
                "Description": "The ExternalId provided by CloudTwin AI",
            },
            "CloudTwinAccountId": {
                "Type": "String",
                "Description": "The AWS Account ID where CloudTwin AI backend runs (your account ID for self-hosted)",
            },
        },
        "Resources": {
            "CloudTwinReadOnlyRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "CloudTwinAI-ReadOnly",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Ref": "CloudTwinAccountId"}},
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": {"Ref": "ExternalId"}
                                    }
                                },
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/SecurityAudit",
                        "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    ],
                },
            }
        },
        "Outputs": {
            "RoleArn": {
                "Value": {"Fn::GetAtt": ["CloudTwinReadOnlyRole", "Arn"]},
                "Description": "Paste this Role ARN into CloudTwin AI",
            }
        },
    }
    return template


def _to_response(account: AwsAccount, compliance_score: float | None = None) -> AwsAccountResponse:
    return AwsAccountResponse(
        id=account.id,
        account_alias=account.account_alias,
        role_arn=account.role_arn,
        external_id=account.external_id,
        aws_account_id=account.aws_account_id,
        is_active=account.is_active,
        last_scanned_at=str(account.last_scanned_at) if account.last_scanned_at else None,
        compliance_score=compliance_score,
    )
