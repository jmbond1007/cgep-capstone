######################################################################
# Layer 1 — GRC baseline (Terraform): KMS
# Customer-managed key for PHI at rest.
# Closes GAP-01 (S3 uploads bucket) and GAP-02 (DynamoDB table).
######################################################################

resource "aws_kms_key" "phi" {
  description             = "Customer-managed key for Acme Health PHI at rest (S3 uploads + DynamoDB submissions)"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi"
  target_key_id = aws_kms_key.phi.key_id
}
