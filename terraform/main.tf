provider "aws" {
  region = var.aws_region
  # Using a profile is more secure than hardcoding credentials
  profile = var.aws_profile
}

# Zip the Lambda function code for deployment
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/security_monitor.py"
  output_path = "${path.module}/security_monitor.zip"
}

# SNS topic for security alerts - all security events will be sent here
resource "aws_sns_topic" "security_alerts" {
  name = "${var.resource_prefix}-security-alerts-topic"
  
  # Optional: Add a display name for SMS messages
  # display_name = "AWS Security Alerts"
  
  tags = merge(
    var.tags,
    {
      Name = "${var.resource_prefix}-security-alerts"
      Description = "Topic for AWS security monitoring alerts"
    }
  )
}

# IAM role for the Lambda function
resource "aws_iam_role" "lambda_role" {
  name = "${var.resource_prefix}-lambda-role"
  description = "Role for security monitoring Lambda function"

  # Trust relationship policy document
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.resource_prefix}-lambda-role"
    }
  )
}

# IAM policy for the Lambda function
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.resource_prefix}-lambda-policy"
  description = "Policy for security monitoring Lambda function"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "sns:Publish"
        ]
        Effect   = "Allow"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Lambda function for security monitoring
resource "aws_lambda_function" "security_monitor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.resource_prefix}-security-monitor"
  role             = aws_iam_role.lambda_role.arn
  handler          = "security_monitor.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.9"
  
  # Increased timeout to handle potential API throttling
  timeout          = 30
  
  # Minimal memory needed for this function
  memory_size      = 128

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      # Add more environment variables as needed
      LOG_LEVEL     = var.environment == "prod" ? "INFO" : "DEBUG"
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.resource_prefix}-security-monitor"
      Description = "Lambda function for monitoring AWS security events"
    }
  )
}

###########################################
# CloudWatch Event Rules for Security Events
###########################################

# 1. IAM User Creation Events
resource "aws_cloudwatch_event_rule" "iam_user_creation" {
  name        = "${var.resource_prefix}-iam-user-creation"
  description = "Capture IAM user creation events"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateUser"]
    }
  })

  tags = var.tags
}

# 2. IAM Access Key Creation Events
resource "aws_cloudwatch_event_rule" "iam_access_key_creation" {
  name        = "${var.resource_prefix}-iam-access-key-creation"
  description = "Capture IAM access key creation events"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateAccessKey"]
    }
  })

  tags = var.tags
}

# 3. S3 Bucket Policy Change Events
resource "aws_cloudwatch_event_rule" "s3_bucket_policy_changes" {
  name        = "${var.resource_prefix}-s3-bucket-policy-changes"
  description = "Capture S3 bucket policy change events"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = [
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl"
      ]
    }
  })

  tags = var.tags
}

# 4. Security Group Ingress Rule Change Events
resource "aws_cloudwatch_event_rule" "security_group_ingress_changes" {
  name        = "${var.resource_prefix}-security-group-ingress-changes"
  description = "Capture security group ingress rule change events"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = [
        "AuthorizeSecurityGroupIngress",
        "ModifySecurityGroupRules"
      ]
    }
  })

  tags = var.tags
}

###########################################
# CloudWatch Event Targets
###########################################

resource "aws_cloudwatch_event_target" "iam_user_creation_target" {
  rule      = aws_cloudwatch_event_rule.iam_user_creation.name
  target_id = "security-monitor-lambda"
  arn       = aws_lambda_function.security_monitor.arn
}

resource "aws_cloudwatch_event_target" "iam_access_key_creation_target" {
  rule      = aws_cloudwatch_event_rule.iam_access_key_creation.name
  target_id = "security-monitor-lambda"
  arn       = aws_lambda_function.security_monitor.arn
}

resource "aws_cloudwatch_event_target" "s3_bucket_policy_changes_target" {
  rule      = aws_cloudwatch_event_rule.s3_bucket_policy_changes.name
  target_id = "security-monitor-lambda"
  arn       = aws_lambda_function.security_monitor.arn
}

resource "aws_cloudwatch_event_target" "security_group_ingress_changes_target" {
  rule      = aws_cloudwatch_event_rule.security_group_ingress_changes.name
  target_id = "security-monitor-lambda"
  arn       = aws_lambda_function.security_monitor.arn
}

###########################################
# Lambda Permissions for CloudWatch Events
###########################################

resource "aws_lambda_permission" "iam_user_creation_permission" {
  statement_id  = "AllowExecutionFromCloudWatchIAMUserCreation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_user_creation.arn
}

resource "aws_lambda_permission" "iam_access_key_creation_permission" {
  statement_id  = "AllowExecutionFromCloudWatchIAMAccessKeyCreation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_access_key_creation.arn
}

resource "aws_lambda_permission" "s3_bucket_policy_changes_permission" {
  statement_id  = "AllowExecutionFromCloudWatchS3BucketPolicyChanges"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_bucket_policy_changes.arn
}

resource "aws_lambda_permission" "security_group_ingress_changes_permission" {
  statement_id  = "AllowExecutionFromCloudWatchSecurityGroupIngressChanges"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_group_ingress_changes.arn
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}
