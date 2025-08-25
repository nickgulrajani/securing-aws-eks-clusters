# -----------------------------------------------------------------------------
# Project / Environment Metadata
# -----------------------------------------------------------------------------
project     = "eks-security"
environment = "dryrun"
aws_region  = "us-east-1"
name_prefix = "ekssec"

# -----------------------------------------------------------------------------
# Feature Toggles
# -----------------------------------------------------------------------------
# Set to true to provision EKS cluster (dry-run safe)
enable_eks = true

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
# These are placeholder subnet IDs for dry-run purposes.
# Replace them with real subnet IDs when applying for real.
private_subnet_ids = [
  "subnet-aaaa1111",
  "subnet-bbbb2222"
]

# -----------------------------------------------------------------------------
# IAM Role for EKS Control Plane (Placeholder)
# -----------------------------------------------------------------------------
# This is required by the aws_eks_cluster resource.
# In dry-run mode, we’re using a fake ARN so there are no charges.
cluster_role_arn = "arn:aws:iam::111111111111:role/placeholder-eks-role"

