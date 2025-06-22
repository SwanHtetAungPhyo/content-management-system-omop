variable "cognito_user_pool_name" {
  default = "content-management-sytem-user-pool"
  type =  string
  description = "User Pool for the content management system"
}

variable "aws-region" {
  default = "us-east-1"
  type = string
  description = "AWS region"
}


variable "cognito_user_pool_client" {
  type = string
  default = "cms-user-pool-client"
  description = "Name of the app client"
}