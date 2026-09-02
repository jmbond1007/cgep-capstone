######################################################################
# Layer 1 - GRC baseline (Terraform): evidence vault
# S3 bucket with Object Lock (COMPLIANCE mode) for the signed pipeline
# evidence produced in Layer 3. Retention: 6 years, per HIPAA's own
# documentation-retention rule (45 CFR 164.316(b)(2)(i)).
######################################################################

resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 6
    }
  }

  # Object Lock configuration requires versioning to be enabled first.
  # There's no direct resource reference between them, so this makes
  # the ordering explicit rather than relying on luck.
  depends_on = [aws_s3_bucket_versioning.evidence]
}
