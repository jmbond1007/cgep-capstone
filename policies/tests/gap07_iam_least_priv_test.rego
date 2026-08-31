package compliance.gap07_test
import rego.v1
import data.compliance.gap07_iam_least_priv_aws as gap07

compliant := {"configuration": {"root_module": {"resources": [
  {"address": "data.aws_iam_policy_document.lambda_inline", "mode": "data",
   "type": "aws_iam_policy_document", "name": "lambda_inline",
   "expressions": {
     "statement": [
       {"sid": {"constant_value": "DynamoDBWrite"}, "effect": {"constant_value": "Allow"},
        "actions": {"constant_value": ["dynamodb:PutItem"]},
        "resources": {"references": ["aws_dynamodb_table.intake.arn"]}},
       {"sid": {"constant_value": "S3Write"}, "effect": {"constant_value": "Allow"},
        "actions": {"constant_value": ["s3:PutObject"]},
        "resources": {"references": ["aws_s3_bucket.uploads.arn"]}},
       {"sid": {"constant_value": "KMSUse"}, "effect": {"constant_value": "Allow"},
        "actions": {"constant_value": ["kms:GenerateDataKey", "kms:Decrypt"]},
        "resources": {"references": ["aws_kms_key.phi.arn"]}}
     ]
   }}
]}}}

wildcard_reintroduced := {"configuration": {"root_module": {"resources": [
  {"address": "data.aws_iam_policy_document.lambda_inline", "mode": "data",
   "type": "aws_iam_policy_document", "name": "lambda_inline",
   "expressions": {
     "statement": [
       {"sid": {"constant_value": "DynamoDBWrite"}, "effect": {"constant_value": "Allow"},
        "actions": {"constant_value": ["dynamodb:*"]},
        "resources": {"references": ["aws_dynamodb_table.intake.arn"]}},
       {"sid": {"constant_value": "S3Write"}, "effect": {"constant_value": "Allow"},
        "actions": {"constant_value": ["s3:*"]},
        "resources": {"references": ["aws_s3_bucket.uploads.arn"]}}
     ]
   }}
]}}}

test_compliant_passes if { count(gap07.deny) == 0 with input as compliant }

test_wildcard_reintroduced_fails if {
    msgs := {msg | some msg in gap07.deny} with input as wildcard_reintroduced
    count(msgs) == 2
    some msg in msgs
    contains(msg, "GAP-07")
}
