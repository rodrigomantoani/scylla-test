output "lambda_function_name" {
  description = "Name of the created Lambda function"
  value       = aws_lambda_function.security_monitor.function_name
}

output "lambda_function_arn" {
  description = "ARN of the created Lambda function"
  value       = aws_lambda_function.security_monitor.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "monitored_events" {
  description = "List of monitored security events"
  value = [
    "IAM User Creation",
    "IAM Access Key Creation",
    "S3 Bucket Policy Changes",
    "Security Group Ingress Rule Changes"
  ]
}
