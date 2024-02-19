import json, ast
import boto3,os,shutil
import datetime
import logging
import warnings
import hashlib
import urllib3, requests
from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter
import zipfile,glob
import time

logging.basicConfig(level=logging.INFO)

now_time = datetime.datetime.now()
headers = {
  'Content-Type': 'application/json; charset=UTF-8'
}
BASE_VENV_PATH = "/tmp/python"
AWS_CONFIG = os.environ.get("AWS_CONFIG",None)
SLACK_BASE_URL = os.environ.get("SLACK_BASE_URL", None)
BUCKETNAME = os.environ.get("BUCKETNAME",None)
KMSKEYARN = os.environ.get("KMSKEYARN",None)
INSPECTOR_REPORT_FORMAT = "CYCLONEDX_1_4"
INSPECTOR_FIX_RESOURCE_TYPE = "AWS_LAMBDA_FUNCTION"
AWS_REGION= os.environ.get("AWS_REGION",None)

warnings.filterwarnings("ignore")

class CustomSslContextHttpAdapter(HTTPAdapter):
        """"Transport adapter" that allows us to use a custom ssl context object with the requests."""
        def init_poolmanager(self, connections, maxsize, block=False):
            ctx = create_urllib3_context()
            ctx.load_default_certs()
            ctx.check_hostname = False
            ctx.options |= 0x4  # ssl.OP_LEGACY_SERVER_CONNECT
            self.poolmanager = urllib3.PoolManager(ssl_context=ctx)

def slack_blockKit(accountName,layerName, updateStatus, fileSHA256, writeMsg):
    sendMsg_format = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Lambda Layer Update* :checked:"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
				{
					"type": "mrkdwn",
					"text": ":arrow_forward: *Account Name :"+str(accountName)+"*"
				},
				{
					"type": "mrkdwn",
					"text": ":arrow_forward: *Layer Name :"+str(layerName)+"*"
				},
				{
					"type": "mrkdwn",
					"text": ":arrow_forward: *UpdateStatus:"+str(updateStatus)+"*"
				},
				{
					"type": "mrkdwn",
					"text": ":arrow_forward: *File SHA256: "+str(fileSHA256)+"*"
				}
			]
            },
            {
                "type": "rich_text",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "Python3 lib update List"
                            }
                        ]
                    },
                    {
                        "type": "rich_text_list",
                        "style": "bullet",
                        "elements": []
                    }
                ]
            }
        ]
    }

    for lib in writeMsg.split("\n"):
        if len(lib) != 0:
            sendMsg_format["blocks"][3]["elements"][1]["elements"].append(
            {
                    "type": "rich_text_section",
                    "elements": [
                        {
                            "type": "text",
                            "text": lib
                        }
                    ]
                }
            )
            
    return [sendMsg_format]

def venvSet(requirements_lib_version_define):
    try:
        """
        If a folder exists, it is deleted and recreated as it is merged with existing data.
        """
        if os.path.exists(BASE_VENV_PATH) is True:
            shutil.rmtree(BASE_VENV_PATH)

        #r1 = os.popen("mkdir -p "+BASE_VENV_PATH).read()
        command1 = os.popen("python3 -m venv "+BASE_VENV_PATH).read()        
        command2 = os.popen("source "+BASE_VENV_PATH+"/./bin/activate").read()
        
        pwd = [os.path.abspath(os.path.join(BASE_VENV_PATH, ".."))] 
        absolute_pwd = pwd[0]

        require_file_pwd = absolute_pwd+"/requirements.txt" #/tmp/python/requirements.txt
        with open (require_file_pwd, 'w') as f: f.write(requirements_lib_version_define)
        #/tmp/python/lib/python3.11/site-packages
        command3 = os.popen("python3 -m pip install --upgrade pip").read()
        command4 = os.popen("pip3 install -t "+BASE_VENV_PATH+" -r "+require_file_pwd).read()
        
        absolute_pwd = pwd[0]
        pwd = [BASE_VENV_PATH]

        with zipfile.ZipFile(absolute_pwd+"/python.zip", 'w')as layer :
            while len(pwd):
                fname = pwd.pop(0)
                if os.path.isdir(fname):
                    pwd = glob.glob(fname + os.sep + '*') + pwd
                    layer.write(fname, fname.split(absolute_pwd)[-1])
                
                elif (os.path.isfile(fname)):
                    layer.write(fname, fname.split(absolute_pwd)[-1])
        
        
        """
        Zip file Size Checking
        """
        zipFileSize = os.path.getsize(absolute_pwd+"/python.zip")
        logging.info ("file size : {}".format(zipFileSize))

        if zipFileSize == 112:
            return "Library Zip file is null"
        
        else:
            return "Library Install successful"
    
    except Exception as e:
        print (e)
        return 0
    
def compare_versions(versionList):
    vars_a = []
    vars_a = vars_a +versionList
    version1 = []
    version2 = []    
    
    while (len(vars_a) > 0):
        vers1 = vars_a.pop(0)
        vers2 = versionList[versionList.index(vers1)+1]

        if vers1.split(".")[0] != vers2.split(".")[0]:
            version1.append(vers1)
            version2.append(vers2)
        else :
            version1.append(vers1)
            version1.append(vers2)

        vars_a.pop(vars_a.index(vers2))

    return (version1, version2)

def get_latest_version(versions):
    """
    Get the latest version from a list of versions.
    """
    try:
        tuple_versions = [tuple(map(int, (version.split(".")))) for version in versions]
        versions = [x for _, x in sorted(zip(tuple_versions, versions), reverse=True)]
        latest_version = versions[0]
    except Exception as e:
        print(e)
        latest_version = None

    return latest_version

def upload_layer(s3_client, lambda_client, serverlessLayerName):
    pwd = os.path.abspath(os.path.join(BASE_VENV_PATH, ".."))
    try:
        if "python.zip" in os.listdir(pwd):
            zipFilepath = pwd+os.sep+"python.zip"
            file = open(zipFilepath, 'rb')
            fileSHA256 = hashlib.sha256(file.read()).hexdigest()
            file.close()

            KEY = serverlessLayerName+"_"+fileSHA256+".zip"
            with open(zipFilepath, "rb") as f:
                s3_client.upload_fileobj(f, BUCKETNAME, KEY)            

            update_req = lambda_client.publish_layer_version(
                LayerName=serverlessLayerName,
                Description='CVE_update_lambda_check',
                Content={
                    "S3Bucket": BUCKETNAME,
                    "S3Key": KEY
                },
                CompatibleRuntimes=[
                    'python3.8','python3.9','python3.10','python3.11',
                ],
                LicenseInfo='string',
                CompatibleArchitectures=[
                    'x86_64','arm64',
                ]
            )
            updateStatus = update_req["ResponseMetadata"]["HTTPStatusCode"]
            
            if updateStatus == 201:
                return update_req["LayerVersionArn"], updateStatus, fileSHA256
            
            else :
                return "", "updateStatus", "fileSHA256"

        else :
            raise FileExistsError
    
    except FileExistsError as e:
        return e
    
    except Exception as e: 
        # An error occurred (InvalidParameterValueException) when calling the PublishLayerVersion operation: Uploaded file must be a non-empty zip
        logging.info ("Layer Uploads Failed")
        exit()

def collection_severless_vulnerability(inspector_client, s3_client, lambda_client):
    output = {}    
    response = inspector_client.create_sbom_export(
        #reportFormat='CYCLONEDX_1_4'|'SPDX_2_3',
        reportFormat=INSPECTOR_REPORT_FORMAT,
        s3Destination={
            'bucketName': BUCKETNAME,
            'kmsKeyArn': KMSKEYARN
        }
    )
    ## checking if job is completed else wait and retry until job is completed
    while True:
        response = inspector_client.get_sbom_export(
            reportId=response["reportId"]
        )
        
        if response['status'] != 'SUCCEEDED':
            logging.info("Printing aws lambda sbom report. Please wait a moment....")
            time.sleep(30) #Maybe takes about 5 minutes
        else :
            objReportdId = response["reportId"]
            
            break

    inspectorScannList = []
    page_iterator = s3_client.get_paginator("list_objects_v2")

    for page in page_iterator.paginate(Bucket=BUCKETNAME, Prefix=INSPECTOR_REPORT_FORMAT+"_"+"outputs"+"_"+objReportdId+"/account="+deps["account_id"]+"/resource="+INSPECTOR_FIX_RESOURCE_TYPE):
        try:
            bucketObjList = page["Contents"]
        except KeyError:
            break

        for objItem in bucketObjList:
            objectData = s3_client.get_object(Bucket = BUCKETNAME, Key=objItem['Key'])
            lambda_inspect_results = json.loads(objectData["Body"].read().decode('utf-8'))    
            
            """
            If components is [] in the inspector2 scan result, there is no vulnerable content.
            or has not been run in the last 90 days
            """
            if lambda_inspect_results["components"] == []:
                pass
            else : 
                if len(lambda_inspect_results["vulnerabilities"]) == 0:
                    pass
                else:
                    inspectorScannList.append(lambda_inspect_results)

    for inspectorScanninventory in inspectorScannList:        
        for lambdaMetaData in inspectorScanninventory["metadata"]["properties"]:
            if "function_name" in lambdaMetaData["name"]:
                lambdaName = lambdaMetaData["value"]
            
            if "runtime" in lambdaMetaData["name"]:
                runtime = lambdaMetaData["value"]
            
            if "arn" in lambdaMetaData["name"]:
                id = lambdaMetaData["value"]

        output[lambdaName] = {}
        lambdaInfo = lambda_client.get_function(FunctionName= lambdaName)
        
        for layers in lambdaInfo["Configuration"]["Layers"]:
            layerName, layerVersion = layers["Arn"].split(":layer:")[-1].split(":")
            output[lambdaName][layerName] = []
            output[lambdaName][layerName].append({
                    "version":layerVersion, 
                    "id":id,
                    "runtimeSetting":runtime.replace("_",".").lower(),
                    "packages":[]
            })
        
        lambdaFinding_inventory = inspector_client.list_findings(
                    filterCriteria={
                        'lambdaFunctionName': [
                            {
                                'comparison': 'EQUALS',
                                'value': lambdaName
                            }
                        ]
                    }
                )
        
        """
        Comparing sbom report and inspector2 findinglings list
        """
        packages = []
        """
        aws inspector service -> findings -> by lambda function -> findings -> Title value
        ex:) vulnerability_pkg 
        ['certifi']
        ['urllib3']
        ['certifi']
        ['future']
        ['urllib3']
        ['requests']
        """
        vulnerability_libName = [vulnerability_pkg["name"]
                             for finding_inventory in lambdaFinding_inventory["findings"] for vulnerability_pkg in finding_inventory["packageVulnerabilityDetails"]["vulnerablePackages"]]
        vulnerability_libName = list(set(vulnerability_libName))

        for pkg in inspectorScanninventory["components"]:
            if pkg["name"] in vulnerability_libName: #If a vulnerability exists in the library file within components
                vulnerability_pkginfo = [vulnerability_pkg
                             for finding_inventory in lambdaFinding_inventory["findings"] for vulnerability_pkg in finding_inventory["packageVulnerabilityDetails"]["vulnerablePackages"] if vulnerability_pkg["name"] == pkg["name"]]
                
                installPkgVersion = [pkg["version"] for pkg in vulnerability_pkginfo].pop()
                pkg["version"] = installPkgVersion
                pkg["cveInfo"] = vulnerability_pkginfo

            else :
                pass

            packages.append(pkg) 

        output[lambdaName][vulnerability_pkginfo[0]["sourceLambdaLayerArn"].split(":layer:")[-1].split(":")[0]][0]["packages"]= packages
        output[lambdaName][vulnerability_pkginfo[0]["sourceLambdaLayerArn"].split(":layer:")[-1].split(":")[0]][0]["updateFlag"] = True

    return output

if __name__ == "__main__":
    aws_config = ast.literal_eval(AWS_CONFIG)
    updateSuccess = []
    
    for aws_env in aws_config:
        aws_access_key_id = aws_env["AWS_ACCESS_KEY"]
        aws_secret_access_key = aws_env["AWS_SECRET_KEY"]
        account_id = aws_env["Account ID"]
        account_name = aws_env["Account Name"]
        
        deps = {
            "access_key": aws_access_key_id,
            "secret_key": aws_secret_access_key,
            "account_id":account_id,
            "account_name":account_name
        }
        lambda_client = boto3.client("lambda", aws_access_key_id = deps["access_key"], aws_secret_access_key= deps["secret_key"], region_name = AWS_REGION)
        s3_client = boto3.client("s3", aws_access_key_id = deps["access_key"], aws_secret_access_key= deps["secret_key"], region_name = AWS_REGION)
        inspector_client = boto3.client("inspector2", aws_access_key_id = deps["access_key"], aws_secret_access_key= deps["secret_key"], region_name = AWS_REGION)


        serverless_vulnerability_dic = collection_severless_vulnerability(inspector_client, s3_client, lambda_client)

        for serverlessName in serverless_vulnerability_dic:
            """
            Multiple layers can be used in a single Lambda.
            """
            for layerName in serverless_vulnerability_dic[serverlessName].keys():
                accountId = serverless_vulnerability_dic[serverlessName][layerName][0]["id"].split(":function")[0].split(AWS_REGION+":")[-1]

                if account_id == accountId:
                    if (layerName not in updateSuccess) and ("python" in serverless_vulnerability_dic[serverlessName][layerName][0]["runtimeSetting"].lower()) :
                        """
                        updateFlag is the inserted key in the case of a layer where a CVE exists when collecting Prisma data.
                        """
                        if  "updateFlag" in serverless_vulnerability_dic[serverlessName][layerName][0].keys(): 
                            writeMsg = ""
                            for packages in serverless_vulnerability_dic[serverlessName][layerName][0]["packages"]:
                                """
                                Loop to create separate requirements.txt for vulnerability library only
                                """
                                try :
                                    if "cveInfo" in packages.keys():
                                        libCVE = list(filter(lambda cveinfo: cveinfo["name"] == packages["name"], packages["cveInfo"]))
                                        update_require_releaesVersion = [ i["fixedInVersion"] for i in libCVE if i["fixedInVersion"] != "No"]
                                        ['2.0.6, 1.26.17', '2.0.7, 1.26.18']
                                        ['42.3.2, 42.2.25', '42.3.8, 42.5.1, 42.4.3, 42.2.27', '42.3.7, 42.4.1, 42.2.26']
                                        #release major version >=2 ex:) python2.7, 3.7, urllib 2.0.7, 1.26.18
                                        majorRelease_version = list(set([release.replace(" ","").split(".")[0] for release in sum([x.split(",") for x in update_require_releaesVersion if "," in x], []) ]))

                                        if len(majorRelease_version) ==1:
                                            updateVersion = get_latest_version([version.replace(" ","") for version in sum([x.split(",") for x in update_require_releaesVersion if "," in x], []) ])
                                            writeMsg = writeMsg + str(packages["name"])+">="+updateVersion+"\n"

                                        elif len(majorRelease_version) ==2:
                                            updateVersion = [version.replace(" ","") for version in sum([x.split(",") for x in update_require_releaesVersion if "," in x], []) ]
                                            releaseVersion_1, releaseVersion_2= compare_versions(updateVersion)
                                            tmp = get_latest_version(releaseVersion_1)
                                            requireVersion = str(packages["name"])+">="+tmp+"\n"
                                            tmp = ""
                                            tmp = get_latest_version(releaseVersion_2)    
                                            writeMsg = writeMsg + requireVersion+str(packages["name"])+">="+tmp+"\n"

                                        else :                                                
                                            updateVersion = update_require_releaesVersion.pop()
                                            writeMsg = writeMsg + str(packages["name"])+">="+updateVersion+"\n"
                                            
                                        

                                    #Although there is no vulnerability, library dependencies that exist in the existing layer are added to requirements.txt to ensure layer integrity.
                                    else :
                                        writeMsg = writeMsg+ str(packages["name"])+">="+str(packages["version"])+"\n"                                                        

                                except ValueError as e:
                                    """
                                    To collect Lib information within a layer where no CVE exists.
                                    The purpose of the above task is to add Lib that has no dependencies or vulnerabilities to the existing layer.
                                    """
                                    writeMsg = writeMsg+ str(packages["name"])+">="+str(packages["version"])+"\n"

                            #backports.zoneinfo>=0.2.1 #https://bobbyhadz.com/blog/python-error-could-not-build-wheels-for-backports-zoneinfo
                            #As shown above, in the case of a specific Lib, the method of adding requirements.txt is to change the format rather than [Lib][inequality][Version].
                            if writeMsg.find('backports.zoneinfo') > 0:
                                writeMsg = [writeMsg.replace(libName, 'backports.zoneinfo;python_version<"3.9"')  for libName in writeMsg.split("\n") if "backports.zoneinfo" in libName ].pop()
                            
                            if writeMsg.find('aws-dd-forwarder>=0.0.0.dev0') > 0:
                                writeMsg = [writeMsg.replace(libName, '')  for libName in writeMsg.split("\n") if "aws-dd-forwarder>=0.0.0.dev0" in libName ].pop()
                            
                            try :
                                venvSet_results = venvSet(writeMsg)
                                
                                if venvSet_results == "Library Install successful":
                                    newlayerVersionArn, updateStatus, fileSHA256 = upload_layer(s3_client, lambda_client, layerName)
                                    if newlayerVersionArn:
                                        logging.info ("{} updateing....".format(layerName))
                                        for updateTarget_lambda in [lambdaName for lambdaName in serverless_vulnerability_dic if layerName in serverless_vulnerability_dic[lambdaName].keys()]:
                                            lambda_config = lambda_client.get_function(
                                                FunctionName = updateTarget_lambda
                                            )
                                            newConfig = []
                                            existingConfig = lambda_config["Configuration"]["Layers"]
                                            newConfig = existingConfig + newConfig
                                            newConfig.append(newlayerVersionArn)

                                            lambdaNewLayer_publish_results = lambda_client.update_function_configuration(
                                                FunctionName=updateTarget_lambda,
                                                Layers=newConfig
                                            )
                                            
                                    
                                else :
                                    fileSHA256 = "None"
                                    raise FileExistsError
                            
                            except FileExistsError as e:
                                updateStatus = "Python virtualization Lib Install"
                            
                            except Exception as e:
                                updateStatus = "Layer Update Error"
                                    
                            """
                            Slack msg
                            """
                            logging.info("'{} Layer Update Finished'".format(layerName))
                            accountName = [aws_env["Account Name"] for aws_env in aws_config if aws_env["Account ID"] == accountId].pop()
                            attachments_msg = slack_blockKit(accountName,layerName, updateStatus, fileSHA256, writeMsg)
                            slackSession = requests.Session()
                            slackSession.mount(SLACK_BASE_URL, CustomSslContextHttpAdapter())
                            response = slackSession.post(SLACK_BASE_URL, headers={'Content-type': 'application/json'}, data=json.dumps({"attachments":attachments_msg }), verify=False)
                            updateSuccess.append(layerName)
                else:
                    logging.info ("account_id : {}, accountId : {}".format(account_id, accountId))
