import json
import ast
import time
import boto3
import os
import logging
import warnings
import urllib3
import requests
from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter
import utility.aws as awsUtil
from utility.work import COMMON, LMD, EC2
import argparse
import sys

logging.basicConfig(level=logging.INFO)

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


def slack_blockKit(accountName, resourceName, updateStatus, fileSHA256, writeMsg):
    sendMsg_format = {
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Lambda Layer Update* :checked:"},
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": ":arrow_forward: *Account Name :"
                        + str(accountName)
                        + "*",
                    },
                    {
                        "type": "mrkdwn",
                        "text": ":arrow_forward: *Layer Name :"
                        + str(resourceName)
                        + "*",
                    },
                    {
                        "type": "mrkdwn",
                        "text": ":arrow_forward: *UpdateStatus:"
                        + str(updateStatus)
                        + "*",
                    },
                    {
                        "type": "mrkdwn",
                        "text": ":arrow_forward: *File SHA256: "
                        + str(fileSHA256)
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
        ]
    }

    for lib in writeMsg.split("\n"):
        if len(lib) != 0:
            sendMsg_format["blocks"][3]["elements"][1]["elements"].append(
                {
                    "type": "rich_text_section",
                    "elements": [{"type": "text", "text": lib}],
                }
            )

    return [sendMsg_format]


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


def main(vulnerability_update_resource, aws_config):
    updateSuccess = []
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

            awsSess = awsUtil.sessionCreator(deps)
            cmn = COMMON(awsSess.client)
            objReportdId = cmn.export_inspecotrSbom(
                INSPECTOR_REPORT_FORMAT, BUCKETNAME, KMSKEYARN
            )
            print(objReportdId)

            if vulnerability_update_resource == "lambda":
                logging.info(
                    "Extraction completed in lambda {} format \
                             within {} account".format(
                        INSPECTOR_REPORT_FORMAT, deps["account_id"]
                    )
                )
                inspectorScannList = cmn.collection_bucketData(
                    BUCKETNAME,
                    INSPECTOR_REPORT_FORMAT
                    + "_"
                    + "outputs"
                    + "_"
                    + objReportdId
                    + "/account="
                    + deps["account_id"]
                    + "/resource="
                    + VULN_FIX_TARGET_TYPE,
                )

                LMDv1 = LMD(awsSess.client)
                vul_dic = LMDv1.collection_service_vulnerability(inspectorScannList)

                logging.info(
                    "Completed dictation of inspector finding \
                              information existing on Serverless base...."
                )

                for serverlessName in vul_dic:
                    """
                    Multiple layers can be used in a single Lambda.
                    """
                    for layerName in vul_dic[serverlessName].keys():
                        sbomInfo = vul_dic[serverlessName][layerName]
                        print(serverlessName + " " + layerName)

                        if (layerName not in updateSuccess) and (
                            "python" in sbomInfo[0]["runtimeSetting"].lower()
                        ):
                            """
                            updateFlag는 Prisma 데이터 수집 시 CVE가 존재하는
                            Layer의 경우 삽입된 key
                            """
                            if "updateFlag" in sbomInfo[0].keys():
                                rqmts = LMDv1.export_fixVersion(sbomInfo)
                                rqmtsRst = LMDv1.check_dependLib(rqmts)
                                print(rqmtsRst)
                                try:
                                    venvResult = LMDv1.venvSet(rqmtsRst)
                                    print(venvResult)
                                    exit()

                                    if venvResult == "successful":
                                        newArn, status, sha256 = LMDv1.upload_layer(
                                            BUCKETNAME, layerName
                                        )

                                        if newArn is not None:
                                            print("{} updateing....".format(layerName))

                                            """
                                            수정된 Layer를 사용하는 Lambda목록을 리스트
                                            추출 후 업데이트 수행
                                            """
                                            for targetLambda in [
                                                lambdaName
                                                for lambdaName in vul_dic
                                                if layerName
                                                in vul_dic[lambdaName].keys()
                                            ]:
                                                results = LMDv1.newLayer_deploy(
                                                    targetLambda, newArn
                                                )
                                    else:
                                        print("FileExistsError")
                                        fileSHA256 = "None"
                                        raise FileExistsError

                                except FileExistsError as e:
                                    updateStatus = "가상화 Lib 설치"

                                except Exception as e:
                                    updateStatus = "Layer Update 에러"

                                """
                                Slack msg 발송
                                """
                                logging.info("'{} Update Finished'".format(hostId))
                                attachments_msg = slack_blockKit(
                                    deps["account_id"],
                                    hostId,
                                    updateStatus,
                                    fileSHA256,
                                    rqmtsRst,
                                )
                                slackSession = requests.Session()
                                slackSession.mount(
                                    SLACK_WEBHOOK_URL, CustomSslContextHttpAdapter()
                                )
                                response = slackSession.post(
                                    SLACK_WEBHOOK_URL,
                                    headers={"Content-type": "application/json"},
                                    data=json.dumps({"attachments": attachments_msg}),
                                    verify=False,
                                )

                                updateSuccess.append(layerName)
            elif vulnerability_update_resource == "ec2":
                logging.info(
                    "Extraction completed in Inspector {} format \
                             within {} account".format(
                        INSPECTOR_REPORT_FORMAT, deps["account_id"]
                    )
                )
                inspectorScannList = cmn.collection_bucketData(
                    BUCKETNAME,
                    INSPECTOR_REPORT_FORMAT
                    + "_"
                    + "outputs"
                    + "_"
                    + objReportdId
                    + "/account="
                    + deps["account_id"]
                    + "/resource="
                    + VULN_FIX_TARGET_TYPE,
                )

                EC2v1 = EC2(awsSess)
                print (inspectorScannList)
                exit()
                vul_dic = EC2v1.collection_service_vulnerability(inspectorScannList)
                host_vulnerability_UpdateTarget = {}
                logging.info(
                    """
                    Completed dictation of inspector finding information
                    existing on EC2 host base....
                    """
                )

                for hostId in vul_dic:
                    # update를 수행할 EC2 Instance ID마다 refresh 변수
                    updateLib_name = []  # list 변수
                    remediate_command_list = []  # list 변수
                    update_lib = ""
                    host_vulnerability_UpdateTarget[hostId] = {}
                    """
                    EC2 host exception 
                    """
                    if hostId == "i-0029e3fe2f4c5a046":  ## 특정 인스턴스 테스트 수행
                        for finding_inventory in vul_dic[hostId]["findings"]:
                            requireUpdate_lib, remediate_list = (
                                EC2v1.inspectorFinding_export_remediation(
                                    finding_inventory
                                )
                            )
                            if len(remediate_list) == 0:
                                pass

                            else:
                                updateLib_name = updateLib_name + requireUpdate_lib
                                remediate_command_list = (
                                    remediate_command_list + remediate_list
                                )
                        """
                        updateLib_name, remediate_list 그대로 사용해도 되지만,
                        다른 취약점(ex: CVE-2024-1627, CVE-2023-52434) 업데이트를 위해
                        동일한 command가 필요한 경우를 생략하기 위해 중복 제거를 수행함.
                        """
                        # os별 runcommand 호출
                        # https://buly.kr/2UgbxAt
                        if vul_dic[hostId]["runtimeSetting"] == "AMAZON_LINUX_2":
                            awsDocumentName = "AWS-RunShellScript"
                            commands = [
                                "yum update -y "
                                + str(" ".join(list(set(updateLib_name))))
                            ]

                        # elif == "windows":
                        #    awsDocumnetName = "AWS-RunPowerShellScript"
                        else:
                            # DocumentName = "AWS-RunShellScript"
                            commands = ""

                        logging.info(
                            """
                            The query to update '{}' existing
                            in '{}' of '{}' is '{}'
                            """.format(
                                str(" ".join(list(set(updateLib_name)))),
                                vul_dic[hostId]["runtimeSetting"],
                                hostId,
                                commands,
                            )
                        )

                        exit()
                        shellCommand_results = EC2v1.sendRunCommandBook(
                            awsDocumentName, hostId, commands
                        )
            elif vulnerability_update_resource == "ecr":
                pass

if __name__ == "__main__":
    aws_config = ast.literal_eval(AWS_CONFIG)
    options = options_parser()

    if (options.update_target.lower() in ["serverless", "lambda"]) and len(
        aws_config
    ) != 0:
        vulnerability_update_resource = "lambda"
        VULN_FIX_TARGET_TYPE = "AWS_LAMBDA_FUNCTION"

    elif (options.update_target.lower() in ["ec2", "host"]) and len(aws_config) != 0:
        vulnerability_update_resource = "ec2"
        VULN_FIX_TARGET_TYPE = "AWS_EC2_INSTANCE"
    elif (options.update_target.lower() in ["ecr", "image"]) and len(aws_config) != 0:
        vulnerability_update_resource = "ec2"
        VULN_FIX_TARGET_TYPE = "AWS_EC2_INSTANCE"

    else:
        print_help()
        exit()

    main(vulnerability_update_resource, aws_config)