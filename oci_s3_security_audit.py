#!/usr/bin/env python3
import argparse
import sys
import json
import logging

import oci

DEFAULT_CONFIG_FILE = "./config/metadata_config.json"
DEFAULT_BUCKET_LOCATION = "us-east-1"
OUTFILE_NAME = "aws_s3_security_audit"

meta_data = {}

audit_list:dict[str, str] = {
    "datetime": "Audit Date Time"
    , "name": "Bucket Name"
    , "region": "Bucket Region"
    , "versioning": "Bucket Versioning"
    , "tagging": "Bucket Tagging"
    , "encryption": "Bucket Encryption"
    , "logging": "Bucket Logging"
    , "static_website": "Static Website"
    , "acl": "ACL"
    , "cors": "CORS"
    , "ownership_controls": "Ownership Controls"
    , "public_access": "Public Access"
    , "policy": "Policy"
    , "object_count": "Object Count"
}

# Configure logging
logging.basicConfig(filename="./"+OUTFILE_NAME+".log", filemode='w', format="%(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.WARNING, force=True)
logger = logging.getLogger(__name__)

# Create a default config using DEFAULT profile in default location
# Refer to
# https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm#SDK_and_CLI_Configuration_File
# for more info
config = oci.config.from_file()


# Initialize service client with default config file
object_storage_client = oci.object_storage.ObjectStorageClient(config)

# Send the request to service, some parameters are not required, see API
# doc for more info
list_buckets_response = object_storage_client.list_buckets(
    namespace_name="idrw0j0fjn4v",
    compartment_id="ocid1.tenancy.oc1..aaaaaaaarbccm4fvewf5vxteawrjg5ui2yap2nws3x2jsgty6l5hiuxqygka",
    limit=784)

# Get the data from response
print(list_buckets_response.data)