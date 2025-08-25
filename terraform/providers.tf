provider "aws" {
  region                      = var.aws_region
  # plan-only friendly
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      Owner       = "dry-run-demo"
      CostCenter  = "simulation-only"
    }
  }
}

