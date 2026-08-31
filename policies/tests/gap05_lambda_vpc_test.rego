package compliance.gap05_test
import rego.v1
import data.compliance.gap05_lambda_vpc_aws as gap05

compliant := {"configuration": {"root_module": {"resources": [
  {"address": "aws_lambda_function.intake", "type": "aws_lambda_function", "name": "intake",
   "expressions": {
     "vpc_config": [{
       "security_group_ids": {"references": ["aws_security_group.lambda.id", "aws_security_group.lambda"]},
       "subnet_ids": {"references": ["aws_subnet.private"]}
     }]
   }}
]}}}

no_vpc_config := {"configuration": {"root_module": {"resources": [
  {"address": "aws_lambda_function.intake", "type": "aws_lambda_function", "name": "intake",
   "expressions": {}}
]}}}

wrong_subnet := {"configuration": {"root_module": {"resources": [
  {"address": "aws_lambda_function.intake", "type": "aws_lambda_function", "name": "intake",
   "expressions": {
     "vpc_config": [{
       "security_group_ids": {"references": ["aws_security_group.lambda.id", "aws_security_group.lambda"]},
       "subnet_ids": {"references": ["aws_subnet.public"]}
     }]
   }}
]}}}

test_compliant_passes if { count(gap05.deny) == 0 with input as compliant }

test_no_vpc_config_fails if {
    some msg in gap05.deny with input as no_vpc_config
    contains(msg, "GAP-05")
}

test_wrong_subnet_fails if {
    some msg in gap05.deny with input as wrong_subnet
    contains(msg, "GAP-05")
}
