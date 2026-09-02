package compliance.gap02_test
import rego.v1
import data.compliance.gap02_dynamodb_kms_aws as gap02

compliant := {"configuration": {"root_module": {"resources": [
  {"address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table", "name": "intake",
   "expressions": {
     "server_side_encryption": [{
       "enabled": {"constant_value": true},
       "kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]}
     }]
   }}
]}}}

missing_encryption := {"configuration": {"root_module": {"resources": [
  {"address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table", "name": "intake",
   "expressions": {}}
]}}}

enabled_no_cmk := {"configuration": {"root_module": {"resources": [
  {"address": "aws_dynamodb_table.intake", "type": "aws_dynamodb_table", "name": "intake",
   "expressions": {
     "server_side_encryption": [{
       "enabled": {"constant_value": true}
     }]
   }}
]}}}

test_compliant_passes if { count(gap02.deny) == 0 with input as compliant }

test_missing_encryption_fails if {
    some msg in gap02.deny with input as missing_encryption
    contains(msg, "GAP-02")
}

test_enabled_no_cmk_fails if {
    some msg in gap02.deny with input as enabled_no_cmk
    contains(msg, "GAP-02")
}
