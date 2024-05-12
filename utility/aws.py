import logging
import boto3
import json

logging.basicConfig(level=logging.INFO)

class sessionCreator:
    def __init__(self, deps):
        self.client = boto3.Session(
            aws_access_key_id=deps["access_key"],
            aws_secret_access_key=deps["secret_key"],
            region_name="ap-northeast-2",
        )

export_file = {}
export_file["Accounts Name"] = []
export_file["Service Name"] = []
export_file["Resource Name"] = []
export_file["Tags"] = []

class ec2Util:
    def __init__(self, session):
        self.ec2_client = session.client("ec2")

    def describe_instances(self, instanceID):
        return self.ec2_client.describe_instances(
            InstanceIds=[instanceID]
        )

class iamUtil:
    def __init__(self, session):
        self.iam_client = session.client("iam")

    def list_roles(self, roleArn):
        return self.iam_client.list_roles(
            PathPrefix = roleArn
        )
    
    def get_role(self, roleName):
        return self.iam_client.get_role(
            RoleName = roleName
        )
    
    def list_attached_role_policies(self, roleName):
        return self.iam_client.list_attached_role_policies(
            RoleName=roleName
        )
    
    def get_policy(self, PolicyArn):
        return self.iam_client.list_attached_role_policies(
            PolicyArn=PolicyArn
        )
    
    def get_role_policy(self, roleName):
        return self.iam_client.list_attached_role_policies(
            RoleName=roleName
        )
    
    def list_policy_versions(self, PolicyArn):
        return self.iam_client.list_policy_versions(
            PolicyArn=PolicyArn
        )
    
    def get_policy_version(self, PolicyArn, versionId):
        return self.iam_client.get_policy_version(
            PolicyArn = PolicyArn,
        VersionId=versionId
        )

class inspectorUtil:
    def __init__(self, session):
        self.inspector_client = session.client("inspector2")

    def get_sbom_export(self, reportId):
        return self.inspector_client.get_sbom_export(reportId=reportId)

    def create_sbom_export(self, inspector_report_format, bucketName, kmskeyarn):
        return self.inspector_client.create_sbom_export(
            # reportFormat='CYCLONEDX_1_4'|'SPDX_2_3',
            reportFormat=inspector_report_format,
            s3Destination={"bucketName": bucketName, "kmsKeyArn": kmskeyarn},
        )

    def list_findings(self, filter):
        return self.inspector_client.list_findings(filterCriteria=filter)
    
    def search_vulnerabilities(self, filter):
        return self.inspector_client.search_vulnerabilities(
            filterCriteria = filter
        )

class ssmUtil:
    def __init__(self, session):
        self.ssm_client = session.client("ssm")

    def runCommandBook(self, documnetName, hostId, command):
        return self.ssm_client.ssm.send_command(
            InstanceIds=[hostId],
            DocumentName=documnetName,
            Parameters={"commands": command},
        )

class lmbUtil:
    def __init__(self, session):
        self.lambda_client = session.client("lambda")

    def get_function(self, FunctionName):
        return self.lambda_client.get_function(FunctionName=FunctionName)

    def update_function_configuration(self, lambdaName, addConfig):
        return self.lambda_client.update_function_configuration(
            FunctionName=lambdaName,
            Layers=addConfig,
        )

    def publish_layer_version(self, bucketname, KEY):
        return self.lambda_client.publish_layer_version(
            LayerName="Python3-requests-layer",
            # LayerName=serverlessLayerName,
            Description="CVE_update_lambda_check",
            Content={"S3Bucket": bucketname, "S3Key": KEY},
            CompatibleRuntimes=[
                "python3.8",
                "python3.9",
                "python3.10",
                "python3.11",
            ],
            LicenseInfo="string",
            CompatibleArchitectures=[
                "x86_64",
                "arm64",
            ],
        )

class s3Util:
    def __init__(self, session):
        self.s3_client = session.client("s3")

    def get_paginator(self, action):
        if action == "list_objects_v2":
            return self.s3_client.get_paginator("list_objects_v2")

    def get_object(self, bucketName, obj):
        return self.s3_client.get_object(Bucket=bucketName, Key=obj)

    def upload_fileobj(self, zipFilepath, bucketName, key):
        with open(zipFilepath, "rb") as f:
            self.s3_client.upload_fileobj(f, bucketName, key)
        return self.s3_client.upload_fileobj(f, bucketName, key)