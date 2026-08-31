package compliance.gap04_test
import rego.v1
import data.compliance.gap04_s3_versioning_aws as gap04

compliant := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}},
  {"address": "aws_s3_bucket_versioning.uploads", "type": "aws_s3_bucket_versioning", "name": "uploads",
   "expressions": {
     "bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
     "versioning_configuration": [{"status": {"constant_value": "Enabled"}}]
   }}
]}}}

missing_versioning := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}}
]}}}

suspended := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}},
  {"address": "aws_s3_bucket_versioning.uploads", "type": "aws_s3_bucket_versioning", "name": "uploads",
   "expressions": {
     "bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
     "versioning_configuration": [{"status": {"constant_value": "Suspended"}}]
   }}
]}}}

test_compliant_passes if { count(gap04.deny) == 0 with input as compliant }

test_missing_versioning_fails if {
    some msg in gap04.deny with input as missing_versioning
    contains(msg, "GAP-04")
}

test_suspended_fails if {
    some msg in gap04.deny with input as suspended
    contains(msg, "GAP-04")
}
