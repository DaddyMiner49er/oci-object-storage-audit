import unittest
import sys, os

# my_path = os.path.dirname(os.path.abspath(__file__))
# sys.path.insert(0, my_path + '\\..\\')

# sys.path.insert(1, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(1, '/home/wsmith/dev/projects/oci-s3-security-audit')

from oci_s3_security_audit import parse_args

class TestArguments(unittest.TestCase):

    def test_prefix_region_mismatch(self):
        sys.argv = ["oci_s3_security_audit.py", "--metaconfig", "..\\config\\metadata_config.json", "--prefix", "-us", "--region", "eu-central-1"]
        args = parse_args()
        self.assertTrue(("-us" in args.prefix and "eu-" in args.region) or ("-eu" in args.prefiix and "us-" in args.region), msg=f"Bucket prefix Region mismatch.")

    def test_all_arguments(self):
        sys.argv = ["oci_s3_security_audit.py", "--metaconfig", "..\\config\\metadata_config.json", "--prefix", "a4x", "--name", "a4x-prod-eu", "--region", "eu-central-1"]
        args = parse_args()
        self.assertEqual(args.metaconfig, '..\\config\\metadata_config.json', msg=f"Argument ['--metaconfig', '..\\config\\metadata_config.json' and not ${args.metaconfig}]")
        self.assertEqual(args.prefix, 'a4x')
        self.assertEqual(args.name, 'a4x-prod-eu')
        self.assertEqual(args.region, 'eu-central-1')

    def test_metaconfig(self):
        sys.argv = ["oci_s3_security_audit.py", "--metaconfig", "..\\config\\metadata_config.json"]
        args = parse_args()
        self.assertEqual(args.metaconfig, "..\\config\\metadata_config.json", msg=f"Argument ['--metaconfig', '..\\config\\metadata_config.json' and not ${ args.metaconfig }]")

    def test_prefix(self):
        sys.argv = ["oci_s3_security_audit.py", "--prefix", "a4x"]
        args = parse_args()
        self.assertEqual(args.prefix, "a4x", msg=f"Argument ['--prefix', 'a4x' and not ${ args.prefix }]")

    def test_name(self):
        sys.argv = ["oci_s3_security_audit.py", "--name", "a4x-prod-us"]
        args = parse_args()
        self.assertEqual(args.name, "a4x-prod-us", msg=f"Argument ['--name', 'a4x-prod-us' and not ${ args.name }]")

    def test_region(self):
        sys.argv = ["oci_s3_security_audit.py", "--region", "eu-central-1"]
        args = parse_args()
        self.assertEqual(args.region, "eu-central-1", msg=f"Argument ['--region', 'eu-central-01 and not ${ args.region }]")

if __name__ == "__main__":
    unittest.main