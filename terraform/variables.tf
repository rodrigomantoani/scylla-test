variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS profile to use for authentication"
  type        = string
  default     = "default"
}

variable "resource_prefix" {
  description = "Prefix to add to resource names for uniqueness"
  type        = string
  default     = "aws-sec-monitor"
}

variable "environment" {
  description = "Deployment environment (dev, test, prod)"
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "AWS-Security-Monitor"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

variable "notification_email" {
  description = "Email address to subscribe to the SNS topic for security alerts"
  type        = string
  default     = ""
}
