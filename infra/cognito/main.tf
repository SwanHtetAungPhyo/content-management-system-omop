# AUTHOR : Swan Htet Aung Phyo
# NOTE: cognito user pool and client creation with the content management system

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
  region = "us-east-1"
}

resource "aws_cognito_user_pool" "swan_user_pool" {
  name = var.cognito_user_pool_name
  auto_verified_attributes = ["email"]
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }
  sms_authentication_message = "Your Code is {####}"
  password_policy {
    require_lowercase = true
    minimum_length = 8
    require_numbers = true
    require_symbols = true
    require_uppercase = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

}

resource "aws_cognito_user" "admin" {
  user_pool_id = aws_cognito_user_pool.swan_user_pool.id
  username     = "swanhtetaungp@gmail.com"
  attributes = {
    email = "swanhtetaungp@gmail.com"
    email_verified = "true"
  }
  temporary_password = "Swanhtet1223@"
}

resource "aws_cognito_user_group" "admin_group" {
  name         = "AdminstratorGROUP"
  user_pool_id = aws_cognito_user_pool.swan_user_pool.id
  precedence = 1
}
resource "aws_cognito_user_in_group" "admin_add_group" {
  group_name   = aws_cognito_user_group.admin_group.name
  user_pool_id = aws_cognito_user_pool.swan_user_pool.id
  username     = aws_cognito_user.admin.username
}
resource "aws_cognito_user_pool_client" "swan_user_pool_client" {
  name         = var.cognito_user_pool_client
  user_pool_id = aws_cognito_user_pool.swan_user_pool.id

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]
  enable_token_revocation = true
  prevent_user_existence_errors = "ENABLED"
  id_token_validity = 24
  access_token_validity = 60
  refresh_token_validity = 90
  token_validity_units {
    access_token = "minutes"
    id_token = "hours"
    refresh_token = "days"
  }
}