output "eks_security_summary" {
  value = {
    kms_arn        = aws_kms_key.eks.arn
    kms_alias      = aws_kms_alias.eks.name
    guardduty_on   = true
    cluster_name   = var.enable_eks ? aws_eks_cluster.secure[0].name : "disabled"
    cluster_private_endpoint = var.enable_eks ? aws_eks_cluster.secure[0].vpc_config[0].endpoint_private_access : true
  }
}

