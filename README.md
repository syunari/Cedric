# ALTRPS(Approach to Lamba Threat Response Process with SBOM)
![Build Status](https://img.shields.io/badge/build-3776AB?style=flat&logo=Python&logoColor=white)
![code styke](https://img.shields.io/badge/code%20style-black-000000.svg)

## Project introduction
Have you heard of the serverless Top 10 vulnerabilities that OWASP announced in 2021? They defined security threats that will occur during serverless operations. We need to focus on the "S9 - Known Vulcan Components" vulnerabilities. This vulnerability was defined as the 9th vulnerability, but the recent increase in exploitation cases through SW supply chain vulnerabilities such as SolarWinds and Log4j has led to increased interest in Software Bill of Materials (SBOM), which means software components.

**"ALTRPS"** is Approach to Lambda Threat Response Process with SBOM, a project to address the "S9 - Known Vulgarable Components" of the serverless top 10 vulnerabilities announced by OWASP in 2021. AWS Serverless is a process of extracting vulnerabilities based on the Inspector SBOM specification and distributing update layers for them.

## ALTRPS Architecture
![image](https://github.com/syunari/ALTRPS/assets/117304119/818fb121-08ed-47e9-8760-231ce0d699ac)

## Requirement variable settings
```
export AWS_CONFIG={'Account ID': <AWS Account ID>, 'Account Name':<AWS Account Name>, 'AWS_ACCESS_KEY': <IAM Credential ACCESS KEY>, 'AWS_SECRET_KEY':'<IAM Credential Secret KEY>'}
export BUCKETNAME = <S3 Bucket Name>
export KMSKEYARN=<KMS Customer Key Arn>
```
- AWS_CONFIG : AWS IAM User Credentials
- BUCKETNAME : SBOM Report storage bucket name
- KMSKEYARN : SBOM Report Encryption KMS Customer Key ARN Address

## Usage
```
python serverlessUpdate.py
```

## ✨ Restrictions
For a detailed explanation, please check **[Medium](https://medium.com/@syunari/infrastructure-protection-part-1-approach-to-lamba-threat-response-process-with-sbom-49c1b018a069)** below.
