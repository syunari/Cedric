import json
import os
import shutil
import logging
import hashlib
import zipfile
import glob
import utility.aws as awsUtill
import glob
import time

logging.basicConfig(level=logging.INFO)
BASE_VENV_PATH = "/tmp/python"  # lambda 용
BASE_VENV_PATH = "/Users/eddi/Desktop/layer/python"  # local 용
global s3Util
global inspectUtil
global ssmUtil
global lmdUtil


class COMMON:
    def __init__(self, client):
        self.client = client

    def export_inspecotrSbom(self, inspector_report_format, bucketName, kmskeyarn):
        global inspectUtil
        inspectUtil = awsUtill.inspectorUtil(self.client)
        response = inspectUtil.create_sbom_export(
           inspector_report_format, bucketName, kmskeyarn
        )
        ### checking if job is completed else wait and retry until job is completed
        while True:
            response = inspectUtil.get_sbom_export(
                response["reportId"]
            )
            if response['status'] != 'SUCCEEDED':
                logging.info("Printing aws lambda sbom report. Please wait a moment....")
                time.sleep(30) #약 3분30초 소요
            else :
                objReportdId = response["reportId"]
                break
        
        return objReportdId

    def collection_bucketData(self, bucketName, Prefix):
        global s3Util
        s3Util = awsUtill.s3Util(self.client)

        page_iterator = s3Util.get_paginator("list_objects_v2")
        inspectorScannList = []

        for page in page_iterator.paginate(Bucket=bucketName, Prefix=Prefix):
            try:
                bucketObjList = page["Contents"]
            except KeyError:
                break

            for objItem in bucketObjList:
                objectData = s3Util.get_object(bucketName, objItem["Key"])
                bucket_inspectData = json.loads(
                    objectData["Body"].read().decode("utf-8")
                )

                """
                If components is [] in the inspector2 scan result
                There is no vulnerable content.
                Or, if EC2 Instance inspection permission exists
                """
                if bucket_inspectData["components"] == []:
                    pass
                else:
                    if len(bucket_inspectData["vulnerabilities"]) == 0:
                        pass
                    else:
                        logging.info(
                            "{}".format(bucket_inspectData["metadata"]["properties"][4])
                        )
                        inspectorScannList.append(bucket_inspectData)
        return inspectorScannList


class LMD(COMMON):
    def __init__(self, client):
        self.client = client

    def check_dependLib(self, require_info):
        if require_info.find("backports.zoneinfo") > -1:
            require_info = [
                require_info.replace(
                    libName,
                    'backports.zoneinfo;python_version<"3.9"',
                )
                for libName in require_info.split("\n")
                if "backports.zoneinfo" in libName
            ].pop()

        if require_info.find("aws-dd-forwarder>=0.0.0.dev0") > -1:
            require_info = [
                require_info.replace(libName, "")
                for libName in require_info.split("\n")
                if "aws-dd-forwarder>=0.0.0.dev0" in libName
            ].pop()

        if require_info.find("urllib3") > -1:
            require_info = [
                require_info.replace(
                    libName,
                    'urllib3<2.1,>=1.25.4; python_version >= "3.10"',
                )
                for libName in require_info.split("\n")
                if "urllib3" in libName
            ].pop()

        return require_info

    def export_fixVersion(self, sbomInfo):
        require_Libversion = ""
        for packages in sbomInfo[0]["packages"]:
            # 취약점 라이브러리만 별도
            # requirements.txt 작성
            try:
                if "cveInfo" in packages.keys():
                    libCVE = list(
                        filter(
                            lambda cveinfo: cveinfo["name"] == packages["name"],
                            packages["cveInfo"],
                        )
                    )
                    require_Ver = [
                        i["fixedInVersion"]
                        for i in libCVE
                        if i["fixedInVersion"] != "No"
                    ]
                    """
                    release major version is multiple
                    ex:) python2.7, 3.7
                    urllib 2.0.7, 1.26.18
                    """
                    majorRelease_version = list(
                        set(
                            [
                                release.replace(" ", "").split(".")[0]
                                for release in sum(
                                    [x.split(",") for x in require_Ver if "," in x],
                                    [],
                                )
                            ]
                        )
                    )
                    if len(majorRelease_version) == 1:
                        # print ("release version 1")
                        updateVersion = self.get_latest_version(
                            [
                                version.replace(" ", "")
                                for version in sum(
                                    [x.split(",") for x in require_Ver if "," in x],
                                    [],
                                )
                            ]
                        )
                        print("updateVersion : {}".format(updateVersion))
                        require_Libversion = (
                            require_Libversion
                            + str(packages["name"])
                            + ">="
                            + updateVersion
                            + "\n"
                        )
                        """
                        release major version is two
                        ex:) python2.7, 3.7
                        urllib 2.0.7, 1.26.18
                        """
                    elif len(majorRelease_version) == 2:
                        updateVersion = [
                            version.replace(" ", "")
                            for version in sum(
                                [x.split(",") for x in require_Ver if "," in x],
                                [],
                            )
                        ]
                        releaseVersion_1, releaseVersion_2 = self.compare_versions(
                            updateVersion
                        )
                        tmp = self.get_latest_version(releaseVersion_1)
                        requireVersion = str(packages["name"]) + ">=" + tmp + "\n"
                        tmp = ""
                        tmp = self.get_latest_version(releaseVersion_2)
                        require_Libversion = (
                            require_Libversion
                            + requireVersion
                            + str(packages["name"])
                            + ">="
                            + tmp
                            + "\n"
                        )
                    else:
                        updateVersion = require_Ver.pop()
                        require_Libversion = (
                            require_Libversion
                            + str(packages["name"])
                            + ">="
                            + updateVersion
                            + "\n"
                        )
                # No vulnerabilities exist, but existing
                # Library dependencies that exist in the layer
                # Add requirements.txt
                else:
                    require_Libversion = (
                        require_Libversion
                        + str(packages["name"])
                        + ">="
                        + str(packages["version"])
                        + "\n"
                    )

            except ValueError as e:
                """
                To collect Lib information within a layer where no CVE exists.
                The above task depends on an existing layer or
                Purpose of adding Lib where vulnerabilities do not exist
                """
                require_Libversion = (
                    require_Libversion
                    + str(packages["name"])
                    + ">="
                    + str(packages["version"])
                    + "\n"
                )

        """
        For backports.zoneinfo>=0.2.1 https://buly.kr/1rzrd8
        # For a specific Lib as above, requirements.txt
        To change the format other than [Lib][Unequal][Version].
        """
        return require_Libversion

    def venvSet(self, requirements_lib_version_define):
        try:
            if os.path.exists(BASE_VENV_PATH) is True:
                shutil.rmtree(BASE_VENV_PATH, ignore_errors=True)

            # python3 -m venv /tmp/python
            command1 = os.popen("python3 -m venv " + BASE_VENV_PATH).read()
            # source /tmp/python/bin/activate
            command2 = os.popen("source " + BASE_VENV_PATH + "/bin/activate").read()
            # /Users/eddi/Desktop/layer/python
            pwd = [os.path.abspath(os.path.join(BASE_VENV_PATH, ".."))]
            absolute_pwd = pwd[0]

            require_file_pwd = absolute_pwd + "/requirements.txt"
            # /tmp/python/requirements.txt
            with open(require_file_pwd, "w") as f:
                f.write(requirements_lib_version_define)
            # pip3 install -t /tmp/python -r /tmp/requirements.txt
            command4 = os.popen(
                "pip3 install -t " + BASE_VENV_PATH + " -r " + require_file_pwd
            ).read()
            absolute_pwd = pwd[0]
            pwd = [BASE_VENV_PATH]

            with zipfile.ZipFile(absolute_pwd + "/python.zip", "w") as layer:
                while len(pwd):
                    fname = pwd.pop(0)
                    if os.path.isdir(fname):
                        pwd = glob.glob(fname + os.sep + "*") + pwd
                        layer.write(fname, fname.split(absolute_pwd)[-1])

                    elif os.path.isfile(fname):
                        layer.write(fname, fname.split(absolute_pwd)[-1])

            """
            Zip file Size Checking
            """
            zipFileSize = os.path.getsize(absolute_pwd + "/python.zip")
            
            if zipFileSize == 112:
                return "Null"

            else:
                return "successful"

        except Exception as e:
            return 0

    def compare_versions(versionList):
        vars_a = []
        vars_a = vars_a + versionList
        version1 = []
        version2 = []

        while len(vars_a) > 0:
            vers1 = vars_a.pop(0)
            vers2 = versionList[versionList.index(vers1) + 1]

            if vers1.split(".")[0] != vers2.split(".")[0]:
                version1.append(vers1)
                version2.append(vers2)
            else:
                version1.append(vers1)
                version1.append(vers2)

            vars_a.pop(vars_a.index(vers2))

        return (version1, version2)

    def get_latest_version(versions):
        """
        Get the latest version from a list of versions.
        """
        try:
            tuple_versions = [
                tuple(map(int, (version.split(".")))) for version in versions
            ]

            versions = [
                x for _, x in sorted(zip(tuple_versions, versions), reverse=True)
            ]
            latest_version = versions[0]
        except Exception as e:
            print(e)
            latest_version = None

        return latest_version

    def upload_layer(self, bucketname, serverlessLayerName):
        pwd = os.path.abspath(os.path.join(BASE_VENV_PATH, ".."))
        try:
            if "python.zip" in os.listdir(pwd):
                zipFilepath = pwd + os.sep + "python.zip"
                file = open(zipFilepath, "rb")
                fileSHA256 = hashlib.sha256(file.read()).hexdigest()
                file.close()

                KEY = (
                    "update_resource/" + serverlessLayerName + "_" + fileSHA256 + ".zip"
                )

                uploadRst = s3Util.upload_fileobj(zipFilepath, bucketname, KEY)
                print(uploadRst)
                update_req = lmdUtil.publish_layer_version(bucketname, KEY)
                updateStatus = update_req["ResponseMetadata"]["HTTPStatusCode"]

                if updateStatus == 201:
                    return update_req["LayerVersionArn"], updateStatus, fileSHA256

                else:
                    return None, "updateStatus", "fileSHA256"

            else:
                raise FileExistsError

        except FileExistsError as e:
            return e

        except Exception as e:
            print("Layer Uploads Failed")
            print(e)
            exit()

    def collection_service_vulnerability(self, inspectorScannList):
        global lmdUtil
        lmdUtil = awsUtill.lmbUtil(self.client)

        output = {}
        for scannInventory in inspectorScannList:
            for meetaData in scannInventory["metadata"]["properties"]:
                if "function_name" in meetaData["name"]:
                    lambdaName = meetaData["value"]

                if "runtime" in meetaData["name"]:
                    runtime = meetaData["value"]

                if "arn" in meetaData["name"]:
                    id = meetaData["value"]

            output[lambdaName] = {}
            lambdaInfo = lmdUtil.get_function(lambdaName)

            """
            AWS Lambda in Layer dict
            Among the resource list, what you need is the runtime environment, 
            id: arn value, layerName functionization
            """

            for layers in lambdaInfo["Configuration"]["Layers"]:
                layerName, layerVersion = layers["Arn"].split(":layer:")[-1].split(":")

                output[lambdaName][layerName] = []
                output[lambdaName][layerName].append(
                    {
                        "version": layerVersion,
                        "id": id,
                        "runtimeSetting": runtime.replace("_", ".").lower(),
                        "packages": [],
                    }
                )

            lambdaFinding_inventory = inspectUtil.list_findings(
                {"lambdaFunctionName": [{"comparison": "EQUALS", "value": lambdaName}]}
            )

            """
            sbom report와 inspector2 findlings list를 비교하기
            """
            packages = []
            """
            aws inspector service -> findings \
                -> by lambda function -> findings -> Title value
            ex:) vulnerability_pkg 
            ['certifi']
            ['urllib3']
            ['certifi']
            ['future']
            ['urllib3']
            ['requests']
            """
            vul_libName = [
                vul__pkg["name"]
                for finding_inventory in lambdaFinding_inventory["findings"]
                for vul__pkg in finding_inventory["packageVulnerabilityDetails"][
                    "vulnerablePackages"
                ]
            ]
            vul_libName = list(set(vul_libName))

            for pkg in scannInventory["components"]:
                if (
                    pkg["name"] in vul_libName
                ):  # components 내 라이브러리 파일에 취약점이 존재할 경우
                    vul_pkginfo = [
                        vul_pkg
                        for finding_inventory in lambdaFinding_inventory["findings"]
                        for vul_pkg in finding_inventory["packageVulnerabilityDetails"][
                            "vulnerablePackages"
                        ]
                        if vul_pkg["name"] == pkg["name"]
                    ]

                    installPkgVersion = [pkg["version"] for pkg in vul_pkginfo]
                    installPkgVersion = installPkgVersion.pop()
                    pkg["version"] = installPkgVersion
                    pkg["cveInfo"] = vul_pkginfo

                else:
                    pass

                packages.append(pkg)

            output[lambdaName][
                vul_pkginfo[0]["sourceLambdaLayerArn"]
                .split(":layer:")[-1]
                .split(":")[0]
            ][0]["packages"] = packages

            output[lambdaName][
                vul_pkginfo[0]["sourceLambdaLayerArn"]
                .split(":layer:")[-1]
                .split(":")[0]
            ][0]["updateFlag"] = True

        return output

    def newLayer_deploy(self, targetLambda, newArn):
        """
        수정된 Layer를 사용하는 Lambda목록을 리스트
        추출 후 업데이트 수행
        """
        lambda_config = lmdUtil.get_function(targetLambda)
        newConfig = []
        existCfg = lambda_config["Configuration"]["Layers"]
        newConfig = existCfg + newConfig
        newConfig.append(newArn)
        publish_results = lmdUtil.update_function_configuratio(targetLambda, newConfig)

        return publish_results


class EC2(COMMON):
    def __init__(self, client):
        self.client = client

    def sendRunCommandBook(self, awsDocumentName, hostId, commands):
        global ssmUtil
        ssmUtil = awsUtill.ssmUtil(self.client)
        shellCommand_results = ssmUtil.runCommandBook(awsDocumentName, hostId, commands)

        return shellCommand_results

    def inspectorFinding_export_remediation(self, findings_inventory_vulnerability):
        return [
            cveInfo["name"]
            for cveInfo in findings_inventory_vulnerability[
                "packageVulnerabilityDetails"
            ]["vulnerablePackages"]
        ], [
            cveInfo["remediation"]
            for cveInfo in findings_inventory_vulnerability[
                "packageVulnerabilityDetails"
            ]["vulnerablePackages"]
            if "yum update" in cveInfo["remediation"]
        ]

    def collection_service_vulnerability(self, inspectorScannList):
        """
        AWS Inspector 스캐닝 결과 값 export
        -> Bucket 내 export 파일(resource 별 구분)로 취약점이 존재하는 EC2 Resource 수집
        -> 수집된 EC2 InstanceID로 list_findings의로 취약점 목록을 dict화 형태로 리턴
        ->
        """
        output = {}
        for inspectorScanninventory in inspectorScannList:
            for ec2MetaData in inspectorScanninventory["metadata"]["properties"]:
                if "instance_id" in ec2MetaData["name"]:
                    instance_id = ec2MetaData["value"]

                if "ami" in ec2MetaData["name"]:
                    ami_id = ec2MetaData["value"]

                if "arn" in ec2MetaData["name"]:
                    id = ec2MetaData["value"]

            output[instance_id] = {}
            lambdaFinding_inventory = inspectUtil.list_findings(
                filterCriteria={
                    "resourceId": [{"comparison": "EQUALS", "value": instance_id}]
                }
            )
            output[instance_id]["ami_id"] = ami_id
            output[instance_id]["instance_id"] = instance_id.lower()
            output[instance_id]["runtimeSetting"] = inspectorScanninventory["metadata"][
                "component"
            ]["name"]
            output[instance_id]["findings"] = lambdaFinding_inventory["findings"]
        return output