# AWS Security Monitor

A serverless solution using AWS Lambda to monitor and alert on specific security-related events in your AWS environment.

## Architecture

The solution consists of the following components:

1. **Lambda Function**: A Python function that processes CloudWatch Events and sends notifications.
2. **CloudWatch Event Rules**: Rules that trigger the Lambda function when specific security events occur.
3. **SNS Topic**: A topic for sending notifications about security events.
4. **IAM Roles and Policies**: Necessary permissions for the Lambda function to operate.

## Monitored Security Events

The solution monitors the following security-related events:

1. IAM User Creation
2. IAM User Creating New Programmatic Access Keys
3. S3 Bucket Policy Changes
4. Security Group Ingress Rule Changes

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform (version 0.14 or later)
- Python 3.9 or later (for local testing)

## Deployment

To deploy the solution:

1. Clone this repository
2. Navigate to the terraform directory
3. Initialize Terraform:
   ```bash
   terraform init
   ```
4. Review the deployment plan:
   ```bash
   terraform plan -var="notification_email=YOUR_EMAIL@example.com"
   ```
5. Apply the configuration:
   ```bash
   terraform apply -var="notification_email=YOUR_EMAIL@example.com"
   ```

This will deploy:
- A Lambda function to monitor security events
- CloudWatch Event Rules to trigger the Lambda function
- An SNS topic for notifications
- An SNS subscription for your email (you'll need to confirm the subscription via email)
- IAM roles and policies for permissions

After deployment, Terraform will output:
- The Lambda function name and ARN
- The SNS topic ARN
- The list of monitored security events

## Testing the Solution

After deploying the solution, you need to:

1. **Confirm the SNS Subscription**:
   Check your email for a confirmation message from AWS SNS and click the confirmation link.

2. **Test the Lambda Function Directly**:

   First, create a test event JSON file:

   ```json
   {
     "version": "0",
     "id": "12345678-1234-1234-1234-123456789012",
     "detail-type": "AWS API Call via CloudTrail",
     "source": "aws.iam",
     "account": "123456789012",
     "time": "2023-01-01T12:00:00Z",
     "region": "us-east-1",
     "resources": [],
     "detail": {
       "eventVersion": "1.08",
       "userIdentity": {
         "type": "IAMUser",
         "principalId": "AIDAEXAMPLE",
         "arn": "arn:aws:iam::123456789012:user/Admin",
         "accountId": "123456789012",
         "userName": "Admin"
       },
       "eventTime": "2023-01-01T12:00:00Z",
       "eventSource": "iam.amazonaws.com",
       "eventName": "CreateUser",
       "awsRegion": "us-east-1",
       "sourceIPAddress": "192.0.2.1",
       "userAgent": "AWS Console",
       "requestParameters": {
         "userName": "TestUser"
       },
       "responseElements": {
         "user": {
           "userName": "TestUser",
           "userId": "AIDAEXAMPLE2",
           "arn": "arn:aws:iam::123456789012:user/TestUser",
           "createDate": "2023-01-01T12:00:00Z"
         }
       }
     }
   }
   ```

   Save the above JSON to a file named `test_event.json`. Then invoke the Lambda function:

   ```bash
   # Invoke the Lambda function with the test event
   aws lambda invoke \
       --function-name security-monitor \
       --cli-binary-format raw-in-base64-out \
       --payload file://test_event.json \
       response.json

   # Check the response
   cat response.json
   ```

3. **Trigger Real Security Events**:

   You can trigger real security events to test the end-to-end functionality:

### 1. IAM User Creation Test

```bash
aws iam create-user --user-name TestSecurityUser
```

### 2. IAM Access Key Creation Test

```bash
aws iam create-access-key --user-name TestSecurityUser
```

### 3. S3 Bucket Policy Change Test

First, create a test bucket with a unique name (add your account ID to ensure uniqueness):

```bash
aws s3api create-bucket --bucket test-security-monitor-bucket-<your-account-id> --region us-east-1
```

Then, apply a policy to the bucket:

First, create a bucket policy JSON file:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::test-security-monitor-bucket-<your-account-id>/*"
    }
  ]
}
```

Save the above JSON to a file named `bucket-policy.json`. Then apply the policy:

```bash
# Apply the policy
aws s3api put-bucket-policy --bucket test-security-monitor-bucket-<your-account-id> --policy file://bucket-policy.json
```

Note: This may fail if your account has Block Public Access settings enabled.

### 4. Security Group Ingress Rule Change Test

First, create a test security group:

```bash
aws ec2 create-security-group --group-name test-security-group --description "Test security group"
```

Then, add an ingress rule:

```bash
aws ec2 authorize-security-group-ingress --group-name test-security-group --protocol tcp --port 22 --cidr 0.0.0.0/0
```

## Verifying Test Results

After triggering the events, you should:

1. **Check Your Email**: You should receive email notifications for each security event you triggered.

2. **Check CloudWatch Logs**:
   ```bash
   # List the log streams for the Lambda function
   aws logs describe-log-streams \
       --log-group-name "/aws/lambda/security-monitor" \
       --order-by LastEventTime \
       --descending

   # View the logs for a specific stream
   aws logs get-log-events \
       --log-group-name "/aws/lambda/security-monitor" \
       --log-stream-name "<log-stream-name-from-previous-command>"
   ```

   You can also check the logs in the AWS Console:
   - Go to CloudWatch service
   - Navigate to "Log groups"
   - Select "/aws/lambda/security-monitor"
   - Browse the log streams

3. **Check SNS Topic**:
   In the AWS Console:
   - Go to the SNS service
   - Select your topic
   - Check the "Monitoring" tab for metrics on published messages

## Cleaning Up Test Resources

After testing, clean up the test resources:

```bash
# Delete IAM access keys
aws iam list-access-keys --user-name TestSecurityUser
aws iam delete-access-key --user-name TestSecurityUser --access-key-id <access-key-id>

# Delete IAM user
aws iam delete-user --user-name TestSecurityUser

# Delete S3 bucket
aws s3 rb s3://test-security-monitor-bucket-<your-account-id> --force

# Delete security group
aws ec2 delete-security-group --group-name test-security-group
```

## Checking Notifications

To check if notifications are being sent:

1. Go to the AWS Management Console
2. Navigate to the SNS service
3. Select the "security-alerts-topic"
4. Check the "Monitoring" tab for metrics on published messages

## Cleanup

To remove all resources created by this solution:

```bash
terraform destroy
```

When prompted, type `yes` to confirm the deletion.

## Assumptions and Limitations

1. **CloudTrail Dependency**: This solution assumes that AWS CloudTrail is enabled in your account, as it relies on CloudTrail events.
2. **Notification Delivery**: The solution creates an SNS topic but does not create subscriptions. You'll need to manually subscribe to the topic to receive notifications.
3. **Regional Scope**: The solution is deployed to a single AWS region. For multi-region monitoring, you would need to deploy it to each region.

## Customization

To monitor additional security events:

1. Add new CloudWatch Event Rules in `main.tf`
2. Add corresponding targets and permissions
3. Update the Lambda function to handle the new event types

## Troubleshooting

If you encounter issues:

1. Check the CloudWatch Logs for the Lambda function
2. Verify that CloudTrail is enabled
3. Ensure that the IAM role has the necessary permissions
4. Check that the CloudWatch Event Rules are correctly configured
