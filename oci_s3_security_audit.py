#!/usr/bin/env python3
from encodings import unicode_escape
from faulthandler import is_enabled
import os
import argparse
import sys
import json
import logging

from datetime import datetime
from typing import Optional
from pathlib import Path
from unittest.mock import DEFAULT

import oci
import oci.config

from oci.config import from_file
from oci.logging import LoggingManagementClient
from oci.object_storage import ObjectStorageClient
from oci.exceptions import ServiceError, InvalidConfig
from oci.identity import IdentityClient

# Create a default config using DEFAULT profile in default location
# Refer to
# https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm#SDK_and_CLI_Configuration_File
# for more info
try:
    # Load config (e.g., from ~/.oci/config)
    # config = from_file()
    # config = from_file("~/.oci/config")
    config = from_file("~/.oci/config", "DEFAULT")

    # Initialize client.
    object_storage_client = ObjectStorageClient(config)

except oci.exceptions.ConfigFileNotFound as e:

    # --- 1. Define your config details ---
    p = Path("~/.oci/oci_api_key.pem")
    config_dict = {
        "user": "ocid1.user.oc1..aaaaaaaaky5aaojdnjnagflwhzyughbt3g2dho3mjvqstl3csgh6y2shquna", 
        "tenancy": "ocid1.tenancy.oc1..aaaaaaaarbccm4fvewf5vxteawrjg5ui2yap2nws3x2jsgty6l5hiuxqygka", 
        "region": "us-ashburn-1", 
        "key_file": str(p.expanduser()), 
        "fingerprint": "8c:d9:87:3e:8c:c0:80:e6:bb:f8:9c:6c:e8:a2:c6:84", 
        "compartment_id": "ocid1.tenancy.oc1..aaaaaaaarbccm4fvewf5vxteawrjg5ui2yap2nws3x2jsgty6l5hiuxqygka", 
        "namespace_name": "idrw0j0fjn4v"
    }

    # --- 2. (Optional) Validate the config dictionary ---
    # This checks if the dictionary contains necessary keys and formats [15].
    try:
        oci.config.validate_config(config_dict)
        print("Config dictionary is valid.")
    except oci.exceptions.InvalidConfig as e:
        print(f"Config validation failed: {e}")
        exit()

    # --- 3. Use the config dictionary to create a client ---
    identity_client = IdentityClient(config_dict)

    # --- 4. (Optional) Write it to a file if needed for other tools/profiles ---
    # While not a standard "write_file" function for the core SDK, you can write it manually
    # if you need it in the ~/.oci/config format for CLI or other uses.
    # You would format it like the file structure shown in the docs [3, 9].
    # Example manual writing (not using a specific oci.config function):
    p = Path("~/.oci/config")
    config_file_path = p.expanduser()
    with open(config_file_path, 'w') as f:
        f.write("[DEFAULT]\n") # Or a custom profile name
        for key, value in config_dict.items():
            f.write(f"{key} = {value}\n")
        f.close()
    # print(f"Config saved to {config_file_path}")

    # Now you can load it back:
    config = oci.config.from_file(file_location=str(config_file_path))
    # print(config)

    # Get the current user details using the user OCID from the config
    user_response = identity_client.get_user(config["user"])
    user_data = user_response.data # type: ignore

#     # Print the user's name
#     print(f"Current User Name: {user_data.name}")
#     # Print the user's ID (OCID)
#     print(f"Current User OCID: {user_data.id}")

# print(f"Using the following configuration: {config}")

# DEFAULT_USER_ID = "ocid1.user.oc1..aaaaaaaaky5aaojdnjnagflwhzyughbt3g2dho3mjvqstl3csgh6y2shquna"
# DEFAULT_FINGERPRINT = "8c:d9:87:3e:8c:c0:80:e6:bb:f8:9c:6c:e8:a2:c6:84"
# DEFAULT_KEY_FILE = "C:\\Users\\WayneSmith\\.oci\\oci_api_key.pem"
# DEFAULT_PASSPHRASE = ""
# DEFAULT_REGION = "us-ashburn-1"
# DEFAULT_TENANCY = "ocid1.tenancy.oc1..aaaaaaaarbccm4fvewf5vxteawrjg5ui2yap2nws3x2jsgty6l5hiuxqygka"
DEFAULT_COMPARTMENT_ID = "ocid1.tenancy.oc1..aaaaaaaarbccm4fvewf5vxteawrjg5ui2yap2nws3x2jsgty6l5hiuxqygka"
DEFAULT_NAMESPACE_NAME = "idrw0j0fjn4v"
DEFAULT_LIMIT = 512
DEFAULT_OBJECT_STORAGE_LOG_GROUPNAME = "object-storage-access-log"
DEFAULT_OBJECT_STORAGE_LOG_GROUPID = "ocid1.loggroup.oc1.iad.amaaaaaavkyibziabnk5choatf4wrnqz2rcpwojnarfi2mgybusewxp2ma4q"
DEFAULT_CONFIG_FILE = "./config/metadata_config.json"
DEFAULT_BUCKET_LOCATION = "us-ashburn-1"
FLOWLOG_CONTEXT = "_flowlogs"
OUTFILE_NAME = "oci_s3_security_audit"

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
# timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
log_filename="./"+OUTFILE_NAME+"_"+timestamp
try:
    logging.basicConfig(filename=log_filename+".log", filemode='w', format="%(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.WARNING, force=True)
    logger = logging.getLogger(__name__)
except PermissionError:
    print(f"Error: Permission denied. Check if { log_filename } is open or in a protected folder.")
    exit(0)

# Audit Functions
# Bucket Versioning
def audit_bucket_versioning(bucket):
    """
    Retrieves the versioning state of an OCI Object Storage bucket.

    :param namespace_name: The Object Storage namespace.
    :param bucket_name: The name of the bucket.
    :param compartment_id: The OCID of the compartment where the bucket resides.
    :return: The versioning state ('Enabled', 'Suspended', or 'Disabled').
    """
    # Load OCI config from default file location
    # config = oci.config.from_file()
    # object_storage_client = oci.object_storage.ObjectStorageClient(config)

    # The 'versioning' attribute holds the state
    versioning_state = bucket.versioning

    if (versioning_state == "Disabled"):
        result = False
    elif (versioning_state == "Enabled"):
        result = True
    else:
        result = False
        
    return result

# Audit Bucket Tags
def audit_bucket_tagging(bucket):
    """Audit tags of a given OCI Object Storage Bucket
    
    Args:
        bucket (oci.object_storage.models.bucket.Bucket): an OCI object storage bucket details object.
    """

    # --- Extract Defined Tags ---
    defined_tags = []
    defined_tags = bucket.defined_tags if bucket.defined_tags is not None else ["NoTags"]

    result = json.dumps(defined_tags).replace("'", '"').replace('"', '\"')
    return result

# Audit Bucket Encryption
def audit_bucket_encryption(bucket):
    """Audit encryption of a given OCI Object Storage Bucket
    
    Args:
        object_storage_client (_type_): _description_
        bucket_name (_type_): _description_
    """

    # Bucket Encryptio
    encryption = bucket.kms_key_id
    if bucket.kms_key_id is not None:
        result = True
    else:
        result = True

    return result

# Audit Bucket Logging
def audit_bucket_logging(object_storage_client, namespace_name, bucket_name, prefix: Optional[str]):
    
    list_objects_response = object_storage_client.list_objects(
        namespace_name=namespace_name, 
        bucket_name = bucket_name, 
        prefix = prefix
    )

    bucket_logs = []
    for bucket_log in list_objects_response.data.objects:
        bucket_logs.append(bucket_log.name)

    result = ' '.join(bucket_logs)

    return result

# Audit Log Group Logging
def audit_log_group_logging(bucket_name, prefix):
    """
    Checks the logging status (Read and Write Access Events) for an OCI Object Storage bucket.
    """
    logging_client = LoggingManagementClient(config)
    
    # --- To list configured logs (if using Log Analytics) ---
    log_file_names = []

    list_logs_response = logging_client.list_logs(
        log_group_id=DEFAULT_OBJECT_STORAGE_LOG_GROUPID
    )

    log_list = []
    for log in list_logs_response.data:
        if log is None:
            continue
        else:
            # print(f"Log Display Name: {log.display_name}, Bucket Name: {bucket_name}")
            if (bucket_name in log.display_name):
                log_list.append(
                    {
                        "ID": f"{log.id}", 
                        "Name": f"{log.display_name}",
                        "Enabled": f"{log.is_enabled}"
                    }
                )
    # result = json.dumps(log_list).replace("'", '"').replace('"', '\"')
    if (log_list is not None):
        result = True
    else:
        result = False

    return result

def audit_bucket_website(bucket):
    """Audit website configuration of a given OCI Object Storage Bucket
    
    Args:
        object_storage_client (_type_): _description_
        bucket_name (_type_): _description_
    """
    # Static Website
    # result = "Pre-authentication Request"
    result = False

    return result

# Audit Bucket ACL
def audit_bucket_acl(bucket):
    """ Audit ACL of a given OCI Object Storage Bucket
    
    Args:
        object_storage_client (object): boto3 AWS S3 client object
        bucket_name (string): Name of bucket to audit properties for

    Returns:
        String: True if audit of bucket properties was successful, False if not
    """

    # Get bucket ACL grants
    grants = ["NoACL"]

    result = json.dumps(grants)

    return result

def audit_bucket_cors(bucket):
    """
    Audit CORS of a given OCI Object Storage Bucket
    """
    
    # Get bucket CORS
    cors_rules = [ { "AllowedMethods": ["NoCORSRules"], "AllowedOrigins": ["None"] } ]

    result = json.dumps(cors_rules)

    return result

def audit_bucket_ownership_controls(bucket):
    """
    Audit Ownership Controls of a given OCI Object Storage Bucket
    Args:

    """
    ownership = []
    ownership.append(bucket.created_by if bucket.created_by is not None else "NoOwnershipControls")

    result = ' '.join(ownership)

    return result

def audit_bucket_public_access(bucket) -> bool:
    """
    Audit Public Access of a given OCI Object Storage
    Args:
        s3_resource (_type_): _description_
        bucket (_type_): _description_
    """

    # Inspect ACL for public access
    public_access_type = bucket.public_access_type

    if public_access_type == "NoPublicAccess":
        public_found = False
    elif (public_access_type == "ObjectRead") or (public_access_type == "ObjectReadWithoutList"):
        public_found = True
    else:
        public_found = False

    return public_found

def audit_object_lifecycle_policy(namespace, bucket_name):
    """
    Audit Policy of a given OCI Object Storage Bucket
    Args:
        object_storage_client (object): boto3._description_
        bucket (_type_): _description_
    """

    # Check bucket policy
    result = ""
    try:
        policies = []
        object_lifecycle_policy_response = object_storage_client.get_object_lifecycle_policy(
            namespace_name=namespace,
            bucket_name=bucket_name
        )
        policies = object_lifecycle_policy_response.data # type: ignore
        policy_dict = (''.join([str(policy) for policy in policies.items])).replace("\n", "")
        # policy_dict = policy_dict.replace("\n", "")
        result = json.dumps(policy_dict).encode().decode('unicode_escape')
        # result = result.encode().decode('unicode_escape')
        # result.decode('unicode_escape')
    except oci.exceptions.ServiceError as e:
        result = "NoPolicy"
    except oci.exceptions.ClientError as e:
        print(f"Client Error: {str(e)}")
        raise  
    return result

def audit_bucket_object_count(bucket):
    """Audit object count of a given OCI Object Storage Bucket
    
    Args:
        object_storage_client (_type_): _description_
        bucket_name (_type_): _description_
    """

    object_count = 0

    object_count = bucket.approximate_count
    
    return object_count

def audit_object_storage(object_storage_client, prefix, region_filter):
    """
    Audit OCI Object Storage Buckets in a given region
    Args:
        object_storage_client (_type_): 
        prefix (string) _description_
        region_filter (_type_): _description_
    """
    
    from datetime import datetime

    global config, meta_data, audit_list

    audit_dict = {}

    namespace_name = config.get("namespace_name")
    compartment_id = config.get("compartment_id")
    try:
        list_buckets_response = object_storage_client.list_buckets(
            namespace_name = namespace_name, 
            compartment_id = compartment_id, 
            limit = 999
        )
    except oci.exceptions.ServiceError as e:
        print(f"Error getting bucket list: {e}")
        raise
    except oci.exceptions.ClientError as e:
        print(f"Client Error: {str(e)}")
        raise

    buckets = list_buckets_response.data
        
    # Iterate through all OCI Object Storage Buckets
    bucket_index = 0
    for bucket in buckets:
        bucket_name = bucket.name

        # Exclude the following buckets:
        # 1. Those where prefix is not part of the bucket name.
        # 2. Those that are oci flow_logs.
        if prefix is not None:
            if not prefix in bucket_name:
                continue
        elif FLOWLOG_CONTEXT in bucket_name:
            continue

        bucket = object_storage_client.get_bucket(
            namespace_name = namespace_name, 
            bucket_name = bucket_name, 
            fields = ['approximateCount']
        ).data

        bucket_dict = {}
        bucket_index += 1
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            bucket_dict.update({ "datetime": current_time })
            bucket_dict.update({ "name": bucket_name })
            bucket_dict.update({ "region": region_filter })
            bucket_dict.update({ "versioning": audit_bucket_versioning(bucket) })
            bucket_dict.update({ "tagging": audit_bucket_tagging(bucket) })
            bucket_dict.update({ "encryption": audit_bucket_encryption(bucket) })
            bucket_dict.update({ "logging": audit_log_group_logging(bucket_name, prefix) })
            # bucket_dict.update({ "logging": audit_bucket_logging(object_storage_client, namespace_name, bucket_name, prefix) })
            bucket_dict.update({ "static_website": audit_bucket_website(bucket) })
            bucket_dict.update({ "acl": audit_bucket_acl(bucket) })
            bucket_dict.update({ "cors": audit_bucket_cors(bucket) })
            bucket_dict.update({ "ownership_controls": audit_bucket_ownership_controls(bucket) })
            bucket_dict.update({ "public_access": audit_bucket_public_access(bucket) })
            bucket_dict.update({ "policy": audit_object_lifecycle_policy(namespace_name, bucket_name) })
            bucket_dict.update({ "object_count": audit_bucket_object_count(bucket) })

            audit_dict[bucket_index] = bucket_dict
        except KeyError as e:
            print(f"KeyError occurred: {str(e)}")
            raise
        except IndexError as e:
            print(f"IndexError occurred: {str(e)}")
            raise

    return audit_dict

# Read dynamic metadata config from local file, if available.
def read_metadata(file_path_name):
    """Read JSON metadata configuration from file

    Args:
        path_file_name (str): path and file name where JSON metadata config exists

    Returns:
        str: JSON string of the contents of the metadata config file
    """

    try:
        with open(file_path_name, 'r') as f_in:
            return json.load(f_in)
    except FileNotFoundError:
        print(f"File not found: {file_path_name}")
    except json.JSONDecodeError:
        print(f"Invalid JSON format in {file_path_name}")
    except PermissionError:
        print(f"Permission denied: {file_path_name}")
    except IOError as e:
        print(f"IO error occurred: {str(e)}")

# Resolve the file path and name accounting for parameter supplied and none.
def resolve_fpn(file_path_name: Optional[str] = DEFAULT_CONFIG_FILE) -> str:
    """Resolves the optional file path name or the default value is not supplied

    Args:
        file_path_name (Optional[str], optional): optional file path name string. Defaults to DEFAULT_CONFIG_FILE.

    Returns:
        str: the file path and name in the form of a string or the default value.
    """
    result = file_path_name or DEFAULT_CONFIG_FILE
    return result

# Resolves the metadata configuation file path and name and parses any additional command line arguments
# def parse_args():
def parse_args(file_path_name: str = resolve_fpn()):
    """Resolve metadata configuration file path and name and parse any additional command line arguments

    Args:
        file_path_name (str, optional): metadata confg path and filename. Defaults to resolve_fpn().

    Returns:
        list: the parsed command line arguments to be used elsewhere in the script.
    """
    
    parser=argparse.ArgumentParser(usage="%(prog)s [options]", description="Perform security audit one or all AWS OCI Object Storage Buckets.")
    parser.add_argument("-m", "--metaconfig", type=str, help="Metadata config path and filename.", nargs="?", const=DEFAULT_CONFIG_FILE, default=DEFAULT_CONFIG_FILE)
    parser.add_argument("-p", "--prefix", type=str, help="AWS OCI Object Storage Bucket names having Prefix to audit.", nargs="?")
    parser.add_argument("-n", "--name", type=str, help="AWS OCI Object Storage Bucket Name to audit.", nargs="?")
    parser.add_argument("-r", "--region", type=str, help="AWS OCI Object Storage Buckets in Region to audit.", nargs="?")

    # Try parsing the added arguments
    try:
        args = parser.parse_args()
        return args
    except SystemExit as e:
        print(f"Caught SystemExit with code {e.code}")
        parser.print_help()
        sys.exit(0)

def main():

    global config, object_storage_client, meta_data, audit_list

    audit_dict:dict = {}
    
    # Get command line arguments (if any)
    args = parse_args()

    # read metadata configuration from file or use built-in
    meta_data = read_metadata(args.metaconfig)
    if meta_data is None:
        meta_data = audit_list

    # Used for performance management
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Process started: {start_time}")

    # Operate on a single bucket if name is passed as a command line argument
    name_filter = args.name

    # Set bucket prefix for filtering the buckets list.
    prefix = args.prefix if args.prefix is not None else name_filter

    # Set region for filtering a single region.
    # region_filter = config.get("region")
    region_filter = args.region if args.region is not None else config.get("region")

    # print("Auditing OCI Object Storage with Bucket Prefix: " + (prefix if prefix is not None else "") + (" in Region: " + region_filter if region_filter is not None else ""))

    # Perform an audit on bucket(s) having prefix, bucket name, and region
    audit_dict = audit_object_storage(object_storage_client, prefix, DEFAULT_BUCKET_LOCATION)

    # Log pipe-delimited headers    
    logger.warning("|".join(audit_list.values()))
    
    # Log pipe-delimited audit buckets
    for audit_index in audit_dict:
        audit_item = '|'.join(map(str, audit_dict[audit_index].values()))
        logger.warning(audit_item)
    
    # Write results 
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    # json_filename="./"+OUTFILE_NAME+"_"+timestamp+".json"
    with open(log_filename+".json", "w") as audit_file:
        json.dump(audit_dict, audit_file)
    
    completed_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Process completed: {completed_time}")

if __name__ == "__main__":
    main()