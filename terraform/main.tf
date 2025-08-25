#############################################
# Scenario 5 – EKS Security (plan-only)
#############################################

locals {
  cluster_name = "${var.name_prefix}-cluster-${var.environment}"
}

# KMS for EKS secrets encryption
resource "aws_kms_key" "eks" {
  description         = "KMS key for EKS secrets encryption (dry run)"
  enable_key_rotation = true
  tags = { Name = "${local.cluster_name}-kms" }
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.cluster_name}-secrets"
  target_key_id = aws_kms_key.eks.key_id
}

# GuardDuty detector (plan-only; zero-cost until apply)
resource "aws_guardduty_detector" "this" {
  enable = true
  tags   = { Name = "${var.project}-gd-${var.environment}" }
}

# Hardened EKS control plane (private endpoint + KMS)
resource "aws_eks_cluster" "secure" {
  count    = var.enable_eks ? 1 : 0
  name     = local.cluster_name
  role_arn = var.cluster_role_arn
  version  = "1.29"

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_public_access  = false
    endpoint_private_access = true
    # public_access_cidrs can be omitted since public access is disabled
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  tags = { Name = local.cluster_name }
}

