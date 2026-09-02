package compliance.gap03_test
import rego.v1
import data.compliance.gap03_s3_tls_aws as gap03

compliant := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}},
  {"address": "aws_s3_bucket_policy.uploads_tls_only", "type": "aws_s3_bucket_policy", "name": "uploads_tls_only",
   "expressions": {
     "bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
     "policy": {"references": ["data.aws_iam_policy_document.uploads_tls_only.json", "data.aws_iam_policy_document.uploads_tls_only"]}
   }},
  {"address": "data.aws_iam_policy_document.uploads_tls_only", "mode": "data",
   "type": "aws_iam_policy_document", "name": "uploads_tls_only",
   "expressions": {
     "statement": [{
       "effect": {"constant_value": "Deny"},
       "condition": [{
         "test": {"constant_value": "Bool"},
         "variable": {"constant_value": "aws:SecureTransport"},
         "values": {"constant_value": ["false"]}
       }],
       "resources": {"references": ["aws_s3_bucket.uploads.arn", "aws_s3_bucket.uploads"]}
     }]
   }}
]}}}

no_bucket_policy := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}}
]}}}

wrong_effect := {"configuration": {"root_module": {"resources": [
  {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads",
   "expressions": {"bucket": {"references": ["local.name_prefix", "local.suffix"]}}},
  {"address": "aws_s3_bucket_policy.uploads_tls_only", "type": "aws_s3_bucket_policy", "name": "uploads_tls_only",
   "expressions": {
     "bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
     "policy": {"references": ["data.aws_iam_policy_document.uploads_tls_only.json", "data.aws_iam_policy_document.uploads_tls_only"]}
   }},
  {"address": "data.aws_iam_policy_document.uploads_tls_only", "mode": "data",
   "type": "aws_iam_policy_document", "name": "uploads_tls_only",
   "expressions": {
     "statement": [{
       "effect": {"constant_value": "Allow"},
       "condition": [{
         "test": {"constant_value": "Bool"},
         "variable": {"constant_value": "aws:SecureTransport"},
         "values": {"constant_value": ["false"]}
       }],
       "resources": {"references": ["aws_s3_bucket.uploads.arn", "aws_s3_bucket.uploads"]}
     }]
   }}
]}}}

test_compliant_passes if { count(gap03.deny) == 0 with input as compliant }

test_no_bucket_policy_fails if {
    some msg in gap03.deny with input as no_bucket_policy
    contains(msg, "GAP-03")
}

test_wrong_effect_fails if {
    some msg in gap03.deny with input as wrong_effect
    contains(msg, "GAP-03")
}
