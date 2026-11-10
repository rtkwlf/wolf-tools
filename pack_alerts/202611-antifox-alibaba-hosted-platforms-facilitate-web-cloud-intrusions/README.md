# 2026-11-10: Antifox Agentic Pentesting Platform Used to Steal AWS Credentials and Move Laterally in Compromised Environments

## ANALYSTS
- Arctic Wolf Labs, Adversary Research

## KEY FINDINGS
- Arctic Wolf is tracking the emerging use of self-hosted agentic penetration testing frameworks, including AntiFox, from public cloud infrastructure. In several recently observed intrusions, Alibaba Cloud systems hosting AntiFox interfaces were associated with confirmed malicious actions against internet-facing web services and associated AWS environments.
- AntiFox-linked infrastructure used valid IAM users and, in some instances, utilized an assumed EC2 role to validate credentials and rapidly enumerate dozens of services. While many calls returned `AccessDenied`, successful operations were interspersed throughout the same sequences. Activity eventually progressed to a successful `GetSecretValue` request against a production secret.
- On a compromised IIS server, `w3wp.exe` created an ASPX web shell and spawned operating-system commands that located `web.config` files and configuration backups, read application settings and database connection strings, and copied configuration and log files into a web-accessible upload directory. The exact vulnerability used for code execution was not identified.
- Valid AWS identities were also used for sustained S3 enumeration and object operations, including `GetObject`, `CopyObject`, and `DeleteObject`.

## BACKGROUND
AntiFox is an open source, Chinese language agentic pentesting platform. In the observed intrusions, activity associated with infrastructure hosting AntiFox chained together web exploitation, web-shell deployment, configuration discovery, credential validation, cloud-service enumeration, secret access, and storage operations. Agentic frameworks such as these make penetration testing techniques more accessible to threat actors, while increasing the speed and consistency with which these techniques can be applied in live attacks.

## OBSERVED BEHAVIOR
1. In some activity, the initial foothold was associated with a compromised internet-facing IIS application. Endpoint telemetry showed the application’s w3wp.exe process creating an ASPX web shell and subsequently executing operating-system commands, although the exact vulnerability used to obtain code execution was not identified. In other activity, the actor began with a valid AWS credential obtained through unknown means.

2. On a compromised IIS server, commands run through `w3wp.exe` identified the execution context with `whoami`, enumerated the application directory, checked permissions with `icacls`, and tested the ability to write files into the web root. The creation of an ASPX web shell by w3wp.exe, followed by command execution through the same IIS worker process, suggests compromise through the affected web application.

3. PowerShell commands then used .NET configuration classes to parse `web.config` connection strings and application settings. The actor also enumerated debug and error-log directories and attempted to connect to an internal production database using a credential extracted from the application configuration.

4. AntiFox-linked infrastructure used valid AWS identities to make authenticated requests, including IAM users and, in some instances, an assumed EC2 role. Identity and permission discovery included GetCallerIdentity, GetUser, ListUsers, ListRoles, ListPolicies, and ListKeys. The activity also tested access to service-specific credentials and authorization artifacts, including an attempted Amazon ECR GetAuthorizationToken request.

5. In one intrusion, the AntiFox-linked source cycled through multiple AWS identities and generated hundreds of cross-service API requests within approximately half an hour. Most requests were denied, but successful discovery and secret-access operations were embedded within the same burst.

6. The activity then rapidly enumerated services across the affected AWS environments, including IAM, EC2, S3, Lambda, Secrets Manager, KMS, RDS, ECS, EKS, Redshift, Athena, Glue, Systems Manager, API Gateway, CloudWatch, CloudFormation, DynamoDB, and Amazon Bedrock, using `List`, `Get`, and `Describe` operations. After authorization failures, the activity continued across other services and concentrated on resources that remained accessible.

7. In some instances, the activity progressed from Secrets Manager enumeration to a successful `GetSecretValue` request against a production secret. In other activity, a valid AWS identity was used for S3 discovery and object operations via API calls including `GetCallerIdentity`, `ListBuckets`, `ListObjects`, `ListObjectVersions`, `HeadObject` and `GetObject`, followed by `CopyObject` and `DeleteObject` operations.

## HUNTING GUIDANCE
- Identify AWS API activity originating from hosting providers or autonomous systems not previously associated with the affected identity.

- Look for a single source IP address using multiple AWS access keys, IAM users, or assumed roles within a short period, which can indicate automated testing of a collected credential set.

- Hunt for rapid sequences of `List`, `Get`, and `Describe` operations spanning multiple unrelated AWS services. Confidence increases when the activity originates from a novel hosting ASN and uses Boto3, Botocore, or another scripting-oriented AWS SDK. Do not assume a sequence was unsuccessful because most requests were denied.

- Review GuardDuty findings for anomalous IAM-user behavior, credential-access activity, discovery activity, compromised EC2 credentials, and unusual API calls from hosting infrastructure.

- Hunt for IIS `w3wp.exe` processes spawning `cmd.exe`, `powershell.exe`, `whoami.exe`, `icacls.exe`, archive utilities, and other living-off-the-land utilities.

- Monitor web-application directories for newly created `.aspx` files, especially when done by `w3wp.exe`. This is particularly relevant in directories involved in upload, temporary, image-conversion, or other user-writable directories. Configuration or log files copied into web-accessible directories under `.txt`, image, or other alternate extensions should be viewed suspiciously.

- Hunt for PowerShell commands referencing `System.Web.Configuration.WebConfigurationManager`, `WebConfigurationFileMap`, `VirtualDirectoryMapping`, `ConnectionStrings.ConnectionStrings`, `AppSettings.Settings`, or `[IO.File]::ReadAllText`.

- Correlate web-shell activity with subsequent AWS activity. If a compromised web application stored AWS credentials, SDK configuration, deployment settings, or references to Secrets Manager, malicious AWS use may begin shortly after configuration discovery.

## DEFENSIVE CONSIDERATIONS
- Enable CloudTrail management events and S3 data events for sensitive buckets, and enable S3 versioning and, where appropriate, Object Lock for critical data to limit the impact of unauthorized object deletion.

- Alert on successful `GetSecretValue` activity from novel infrastructure, particularly when preceded by broad service enumeration or access-denied activity.

- Maintain an inventory of internet-facing applications and prioritize file-conversion, upload, and document-processing services that accept user-controlled content for patching, application testing, and web-application firewall coverage.

- Isolate affected web servers immediately when IIS worker processes are observed spawning unexpected command shells or interpreters. Preserve the web root, IIS logs, endpoint telemetry, and memory before reimaging where operationally feasible.

- Remove unauthorized ASPX files and review all user-writable web directories, because attackers may deploy alternate shells or modify existing application files.

- Rotate credentials exposed through `web.config`, application settings, deployment artifacts, debug logs, environment variables, and backup configuration files, including database credentials, AWS access keys, API tokens, encryption keys, and application secrets.

- Revoke active AWS sessions and access keys associated with affected users and roles, and review CloudTrail activity for each identity before creating replacement credentials.

- Enforce IMDSv2 and configure a restrictive metadata response hop limit where EC2 instance roles are required, and apply least-privilege policies to application identities so that workloads do not hold broad listing permissions across the account.

## ADDITIONAL REFERENCES
- https://github.com/AntiFox-AI/antifox

## INDICATORS OF COMPROMISE
The indicators below represent infrastructure and behavioral artifacts associated with the observed activity and should not be considered exhaustive. AntiFox is publicly available, and public-cloud infrastructure may be reassigned or shared with unrelated tenants.

```
# ANTIFOX-LINKED SOURCE INFRASTRUCTURE
47[.]79[.]4[.]33
8[.]208[.]101[.]210

# ANTIFOX WEB INTERFACE TITLE
AntiFox — 自主渗透测试控制台

# ANTIFOX BANNER HASH
c370d03542ed2ec696f7337940b14652e98e9bab

# ANTIFOX COMMON PORT
TCP/8787

# ENDPOINT BEHAVIOR
w3wp.exe → cmd.exe
w3wp.exe → powershell.exe
w3wp.exe → where.exe
cmd.exe → whoami.exe
cmd.exe → icacls.exe

# FILE PATTERNS
<web-accessible upload directory>*.aspx
<web-accessible upload directory>\pwn*.aspx
<web-accessible upload directory>\cfg*.txt
<web-accessible upload directory>\wc*.txt
<web-accessible upload directory>\el*.txt

# AWS API SEQUENCES
ListSecrets → GetSecretValue
GetCallerIdentity → ListBuckets
ListBuckets → ListObjects
ListObjects → HeadObject
ListObjects → GetObject

# USER AGENT STRINGS
Boto3/1.43.125
Botocore/1.43.125
```