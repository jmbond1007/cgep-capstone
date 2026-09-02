package compliance.gap01_test
import rego.v1
import data.compliance.gap01_s3_kms_aws as gap01

compliant := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}},
  {"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
   "type": "aws_s3_bucket_server_side_encryption_configuration", "name": "uploads",
   "expressions": {
     "bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
     "rule": [{
       "apply_server_side_encryption_by_default": [{
         "kms_master_key_id": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
         "sse_algorithm": {"constant_value": "aws:kms"}
       }],
       "bucket_key_enabled": {"constant_value": true}
     }]
   }}
]}}}

missing_encryption := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}}
]}}}

aws_managed_key := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}},
  {"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
   "type": "aws_s3_bucket_server_side_encryption_configuration", "name": "uploads",
   "expressions": {
     "bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
     "rule": [{
       "apply_server_side_encryption_by_default": [{
         "sse_algorithm": {"constant_value": "aws:kms"}
       }],
       "bucket_key_enabled": {"constant_value": true}
     }]
   }}
]}}}

test_compliant_passes if { count(gap01.deny) == 0 with input as compliant }

test_missing_encryption_fails if {
    some msg in gap01.deny with input as missing_encryption
    contains(msg, "GAP-01")
}

test_aws_managed_key_fails if {
    some msg in gap01.deny with input as aws_managed_key
    contains(msg, "GAP-01")
}
