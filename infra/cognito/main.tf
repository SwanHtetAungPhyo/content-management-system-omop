terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws-region
}

resource "aws_cognito_user_pool" "cms_user_pool" {
  name = var.cognito_user_pool_name
}