#!/usr/bin/env python3
import unittest
import sys, os
import oci
import oci.config

from oci.config import from_file
from oci.logging import LoggingManagementClient
from oci.object_storage import ObjectStorageClient
from oci.exceptions import ServiceError, InvalidConfig
from oci.identity import IdentityClient

my_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, my_path + '\\..\\')

DEFAULT_COMPARTMENT_ID = "ocid1.tenancy.oc1..aaaaaaaarbccm4fvewf5vxteawrjg5ui2yap2nws3x2jsgty6l5hiuxqygka"
DEFAULT_NAMESPACE_NAME = "idrw0j0fjn4v"

config = from_file("~/.oci/config", "DEFAULT")
object_storage_client = ObjectStorageClient(config)

import oci_s3_security_audit

class TestAuditResults(unittest.TestCase):

    def setUp(self):
        self.bucket_name = "a4x-prod-us"
        self.prefix = "a4x"
        self.region = "us-ashburn-1"
        self.object_storage_client = ObjectStorageClient(config)
        self.bucket = self.object_storage_client.get_bucket(
            namespace_name = DEFAULT_NAMESPACE_NAME, 
            bucket_name = self.bucket_name, 
            fields = ['approximateCount']
        ).data # type: ignore

    def test_name(self):
        self.assertEqual(self.bucket_name, "a4x-prod-us")

    def test_region(self):
        self.assertEqual(self.region, "us-east-1")

    def test_versioning(self):
        bucket_versioning = oci_s3_security_audit.audit_bucket_versioning(self.bucket)
        self.assertIn(bucket_versioning, [True, False], msg=f"Bucker versioning: True or False and not ${ bucket_versioning }.")

    def test_tagging(self):
        bucket_tagging = oci_s3_security_audit.audit_bucket_tagging(self.bucket)
        self.assertTrue(any(elem in bucket_tagging for elem in ["NoTags", "Key"]), msg=f"Bucket tagging: elements ['NoTags', 'Key'] and not ${ bucket_tagging }.")

    def test_encryption(self):
        bucket_encryption = oci_s3_security_audit.audit_bucket_encryption(self.bucket)
        self.assertIn(bucket_encryption, [True, False], msg=f"Bucket encryption: True or False and not ${ bucket_encryption }.")

    def test_logging(self):
        bucket_logging = oci_s3_security_audit.audit_log_group_logging(self.bucket_name, self.prefix)
        self.assertIn(bucket_logging, [True, False], msg=f"Bucker logging: True or False and not ${ bucket_logging }.")

    def test_static_website(self):
        bucket_static_website = oci_s3_security_audit.audit_bucket_website(self.bucket_name)
        self.assertIn(bucket_static_website, [True, False], msg=f"Bucker static website: True or False and not ${ bucket_static_website }.")

    def test_acl(self):
        bucket_acl = oci_s3_security_audit.audit_bucket_acl(self.bucket_name)
        self.assertTrue(any(elem in bucket_acl for elem in ["NoACL", "ID"]), msg=f"Bucket ACL: elements ['NoACL', 'ID'] and not ${ bucket_acl }.")

    def test_cors(self):
        bucket_cors = oci_s3_security_audit.audit_bucket_cors(self.bucket_name)
        self.assertTrue(any(elem in bucket_cors for elem in ["AllowedMethods", "AllowedOrigins"]), msg=f"Bucket CORS: elements ['AllowedMethods', 'AllowedOrigin'] and not ${ bucket_cors }.")

    def test_ownership_controls(self):
        bucket_ownership_controls = oci_s3_security_audit.audit_bucket_ownership_controls(self.bucket_name)
        self.assertTrue(any(elem in bucket_ownership_controls for elem in ["NoOwnershipControls", "OwnershipControls"]), msg=f"Bucket ownership controls: elements ['NoOwnershipControls', 'OwnershipControls'] and not ${ bucket_ownership_controls }.")

    def test_public_access(self):
        bucket_public_access = oci_s3_security_audit.audit_bucket_public_access(self.bucket_name)
        self.assertIn(bucket_public_access, [True, False], msg=f"Bucker public access: True or False and not ${ bucket_public_access }.")

    def test_policy(self):
        bucket_policy = oci_s3_security_audit.audit_object_lifecycle_policy(self.object_storage_client, self.bucket_name) 
        self.assertTrue(any(elem in bucket_policy for elem in ["NoPolicy", "Statement"]), msg=f"Bucket policy: elements ['NoPolicy', 'Statement'] and not ${ bucket_policy }.")


    def test_object_count(self):
        import numbers
        bucket_object_count = oci_s3_security_audit.audit_bucket_object_count(self.bucket_name)
        self.assertTrue(isinstance(bucket_object_count, int), msg=f"Bucket object count: numeric and not ${ type(bucket_object_count) }.")

if __name__ == "__main__":
    unittest.main