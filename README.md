# OCI S3 Security Audit Tool (OCI-s3-security-audit)

Python script to perform audit of security properties and permissions on OCI S3 (Simple Storage Service) buckets.

## Requirements

* Amazon Web Services [OCI](https://www.oracle.com/cloud/sign-in.html) account.

* Python 3

* OCI SDK for Python (ObjectStorageClient)

## Command Line Arguments

> | Parameter Name | Description | Default Value |
> | -------------- | ----------- | ------------- |
> | -m \| --metaconfig   | Metadata config path and filename. | ./config/metadata_config.json |
> | -p \| --prefix       | OCI S3 bucket names having Prefix to audit. | None |
> | -n \| --name         | OCI S3 bucket Name to audit. | All OCI S3 Buckets |
> | -r \| --region       | OCI S3 buckets in Region to audit. | us-east-1 |

## Metadata Configuration File Formate

The metadata configuration file contains a JSON structure used to build audit results JSON file as well as column names for delimited file.

    {
        "datetime": "Audit Date Time",
        "name": "Bucket Name",
        "region": "Bucket Region",
        "versioning": "Bucket Versioning",
        "tagging": "Bucket Tagging",
        "encryption": "Bucket Encryption",
        "logging": "Bucket Logging",
        "static_website": "Static Website",
        "acl": "ACL",
        "cors": "CORS",
        "ownership_controls": "Ownership Controls",
        "public_access": "Public Access",
        "policy": "Policy",
        "object_count": "Object Count"
    }

## Delimited File Output Format

### A report-style delimited file is output for ingestion into a data warehouse.

#### The default delimiter is the pipe \| symbol given other common delimiters can be part of JSON results (see below)

##### Audit Date Time|Bucket Name|Bucket Region|Bucket Versioning|Bucket Tagging|Bucket Encryption|Bucket Logging|Static Website|ACL|CORS|Ownership Controls|Public Access|Policy|Object Count

2025-11-13 13:13:13|a4x-ai-model-us|us-east-1|False|[{"Key": "costEnv", "Value": "share-us"}]|True|True|False|[{"Grantee": {"ID": "2c7d84a5aacb47fb92f1316a356a050853e2c96327d71fad0f68ed3f63b47aa6", "Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]|[{"AllowedMethods": ["NoCORSRules"], "AllowedOrigins": ["None"]}]|NoOwnershipControls|False|NoPolicy|439
