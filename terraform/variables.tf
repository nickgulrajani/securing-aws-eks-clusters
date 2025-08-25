variable "project" {
  type    = string
  default = "eks-security"
}

variable "environment" {
  type    = string
  default = "dryrun"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "ekssec"
}

# Enable/disable EKS
variable "enable_eks" {
  type    = bool
  default = true
}

# Private subnets for EKS control plane
variable "private_subnet_ids" {
  description = "Private subnet IDs for EKS control plane"
  type        = list(string)
  default     = ["subnet-aaaa1111", "subnet-bbbb2222"]
}

# IAM role for EKS control plane (placeholder for dry-run)
variable "cluster_role_arn" {
  description = "IAM role ARN for EKS control plane"
  type        = string
  default     = "arn:aws:iam::111111111111:role/placeholder-eks-role"
}

