import ast
import os
import json
import logging
import warnings
import urllib3
import requests
from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter
import utility.aws as awsUtil
import argparse
import sys

logging.basicConfig(level=logging.INFO)
global awsSess
try:
    AWS_CONFIG = os.environ["AWS_CONFIG"]
    BUCKETNAME = os.environ["BUCKETNAME"]
    KMSKEYARN = os.environ["KMSKEYARN"]
    SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
    INSPECTOR_REPORT_FORMAT = os.environ["INSPECTOR_REPORT_FORMAT"]
except KeyError as e:
    print(
        """
        A required environment variable does not exist.
        Required environment variables are 'AWS_CONFIG', 'BUCKETNAME',
        'KMSKEYARN', 'INSPECTOR_REPORT_FORMAT', and 'SLACK_WEBHOOK_URL'.
        """
    )
    exit()

warnings.filterwarnings("ignore")

class CustomSslContextHttpAdapter(HTTPAdapter):
    """
    Transport adapter" that allows us to use a custom ssl context object \
    with the requests.
    """

    def init_poolmanager(self, connections, maxsize, block=False):
        ctx = create_urllib3_context()
        ctx.load_default_certs()
        ctx.check_hostname = False
        ctx.options |= 0x4  # ssl.OP_LEGACY_SERVER_CONNECT
        self.poolmanager = urllib3.PoolManager(ssl_context=ctx)

def print_help():
    print("See the examples below to see your options.")
    help_msg = """
    Options :
        -t, --update_target,    This refers to the resource target to \
                                be updated with sbom. ex:) Lambda, EC2, ECR
    """
    print(help_msg)

def options_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--update_target",
        type=str,
        action="store",
        dest="update_target",
        default="False",
    )

    (options) = parser.parse_args()

    if len(sys.argv) < 3:
        print_help()
        sys.exit()

    return options

def slack_blockKit(vulnerability_id, resourceId, resourceTags, PermissionChecker):
    sendMsg_format = {
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*CVE search results* :checked:"},
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": ":arrow_forward: *vulnerability_id :"
                        + str(vulnerability_id)
                        + "*",
                    },
                    {
                        "type": "mrkdwn",
                        "text": ":arrow_forward: *resourceId :"
                        + str(resourceId)
                        + "*",
                    },
                    {
                        "type": "mrkdwn",
                        "text": ":arrow_forward: *PermissionChecker: "
                        + str(PermissionChecker)
                        + "*",
                    },
                ],
            },
            {
                "type": "rich_text",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {"type": "text", "text": "Python3 lib update List"}
                        ],
                    },
                    {"type": "rich_text_list", "style": "bullet", "elements": []},
                ],
            },
            {
                "type": "actions",
			    "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "emoji": True,
                            "text": "Deploy"
                        },
                        "style": "primary",
                        "value": "click_me_123"
                    }
			    ]
            }
        ]
    }

    for key, value in resourceTags.items():
        sendMsg_format["blocks"][3]["elements"][1]["elements"].append(
            {
                "type": "rich_text_section",
                "elements": [{"type": "text", "text": str(key)+" : "+str(value)}],
            }
        )

    return [sendMsg_format]

def ssmChecker(resourceFinding):
    global awsSess
    PermissionChecker = False
    
    if "ec2" in resourceFinding["type"].lower():
        instanceID = resourceFinding["id"]
        ec2Util = awsUtil.ec2Util(awsSess.client)
        iamUtil = awsUtil.iamUtil(awsSess.client)
        ec2Info = ec2Util.describe_instances(instanceID)
        iamArn = ec2Info["Reservations"][0][
            "Instances"][0]["IamInstanceProfile"]["Arn"]
        iamName = iamArn.split("/")[-1]
        attachPolicy = iamUtil.get_role_policy(iamName)
        
        #SSM IAM 권한 체크
        PermissionChecker = [True 
            for policyInfo in attachPolicy["AttachedPolicies"] 
            if policyInfo["PolicyName"] == "AmazonSSMManagedInstanceCore"].pop()
        
    return PermissionChecker
    #elif "lambda" in resourceFinding["type"].lower():
    #    print ("lambda 업데이트 필요, 람다는 layer를 업데이트 해야함")
    #    print (resourceFinding)
    #    lmdArn = resourceFinding["id"]
    #    lmdId = lmdArn.split("function:")[-1].split(":")[0]
    #    print (lmdId)
    #    runtime = resourceFinding["details"][
    #        "awsLambdaFunction"]["runtime"]
    #    print (runtime)

def runtimeChecker(findindInfo):
    checker = False
    if "LAMBDA" in findindInfo["type"]:
        if "PYTHON" in findindInfo["details"]["awsLambdaFunction"]["runtime"]:
            checker = True
        else :
            pass
    elif "EC2" in findindInfo["type"]:
        if "AMAZON" in findindInfo["details"]["awsEc2Instance"]["platform"]:
            checker = True
    return checker
            
def main(vulnerability_id, aws_config):
    for aws_env in aws_config:
        if aws_env["Account Name"] in "To_Be Dev":
            # aws_access_key_id = aws_env["AWS_ACCESS_KEY"]
            # aws_secret_access_key = aws_env["AWS_SECRET_KEY"]
            # account_id = aws_env["Account ID"]
            # account_name = aws_env["Account Name"]

            deps = {
                "access_key": aws_env["AWS_ACCESS_KEY"],
                "secret_key": aws_env["AWS_SECRET_KEY"],
                "account_id": aws_env["Account ID"],
                "account_name": aws_env["Account Name"],
            }
            global awsSess
            awsSess = awsUtil.sessionCreator(deps)
            inspectUtil = awsUtil.inspectorUtil(awsSess.client)

            #AWS Inspector에서 입력 받은 vulnerability 취약점을 제공 여부 확인
            searchVul =inspectUtil.search_vulnerabilities(
                {
                    'vulnerabilityIds': [
                        vulnerability_id
                    ]
                }
            )
            
            """
            Inspector로 취약점 탐지 리소스 목록 수집 및 자동 배포 가능 여부 확인
            """
            if len(searchVul["vulnerabilities"]) > 0:
                detectFlag = "탐지 가능"
                findingList = inspectUtil.list_findings({
                    'vulnerabilityId': [
                        {
                            'comparison': 'PREFIX',
                            'value': vulnerability_id
                        },
                    ]
                })
                affectedList = [vul["resources"] 
                                     for vul in findingList["findings"] 
                                     if len(vul["resources"]) > 0
                ]
                #i-06cb2c6e4fdac48d7
                #i-096a43ba285e2458a
                for findingInfo in affectedList:
                    resourceFinding = findingInfo[0]
                    #lambda는 배포 설정한 python 검사, EC2는 OS 검사
                    PermissionChecker = runtimeChecker(resourceFinding)

                    if PermissionChecker is True:
                        #EC2의 경우 IAM Role에 SSM 권한 추가 검사
                        if "EC2" in resourceFinding["type"]:
                            ssmFlag = ssmChecker(resourceFinding)
                            if ssmFlag is False:
                                PermissionChecker = False    
                    
                    else :
                        PermissionChecker = False

                    print ("{} 취약점 조치 대상 : {}, 설명 : '{}', 조치 가능 여부 {}".format( vulnerability_id, resourceFinding["id"], resourceFinding["tags"],PermissionChecker ) )

                    if "function" in resourceFinding["id"]:
                        resourceFinding["id"] = resourceFinding["id"].split("function:")[-1].split(":")[0]
                    
                    print (resourceFinding["tags"])
                    
                    #checkerDeploy = checkDeploy(resourceFinding)
                    #exit()

                    #if checkerDeploy is True:
                    #    cve_remediate = [
                    #        vul_pkg["remediation"]
                    #        for vul in findingList["findings"]
                    #        for vul_pkg in vul["packageVulnerabilityDetails"][
                    #            "vulnerablePackages"]
                    #    ]
                    #    cve_remediate = list(set(cve_remediate))
                    #    print (cve_remediate)



                        #"""
                        #취약점 조치를 위한 명령어 셋
                        #"""
                        #cve_remediate = [
                        #        vul_pkg["remediation"]
                        #        for vul in findingList["findings"]
                        #        for vul_pkg in vul["packageVulnerabilityDetails"][
                        #            "vulnerablePackages"]
                        #    ]
                        #cve_remediate = list(set(cve_remediate))
                        #print (cve_remediate)

            else :
                detectFlag = "탐지 불가능"
                print (detectFlag)

            attachments_msg = slack_blockKit(vulnerability_id, 
                                   resourceFinding["id"],
                                   resourceFinding["tags"],
                                   PermissionChecker
                                   )
            slackSession = requests.Session()
            slackSession.mount(SLACK_WEBHOOK_URL, 
                                CustomSslContextHttpAdapter()
            )
            print (attachments_msg)
            response = slackSession.post(
                SLACK_WEBHOOK_URL,
                headers={"Content-type": "application/json"},
                data=json.dumps({"attachments": attachments_msg}),
                verify=False,
            )
                    

if __name__ == "__main__":
    aws_config = ast.literal_eval(AWS_CONFIG)
    options = options_parser()

    if ("CVE" in options.update_target.upper() ):
        vulnerability_id = options.update_target.upper()
    
    else :
        print_help()
        exit()
    
    main(vulnerability_id, aws_config)