output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.swan_user_pool.id
  description = "User Pool ID: "
}
output "cognito_user_pool_client" {
  value = aws_cognito_user_pool_client.swan_user_pool_client.id
  description = "User Pool Client : "
}