import json
import boto3
import os
import logging
from datetime import datetime

# Set up logging - increase level for more verbose output during troubleshooting
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
sns = boto3.client('sns')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):
    """
    Main handler function for the AWS Security Monitor Lambda.
    Processes CloudWatch Events for security-related actions and sends notifications.
    
    This function is triggered by CloudWatch Events when specific security-related
    actions occur in the AWS account. It extracts relevant information from the event,
    formats a notification message, and sends it to the configured SNS topic.
    """
    # Log the incoming event for debugging purposes
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract basic event information
        event_name = event.get('detail', {}).get('eventName', 'Unknown')
        event_time = event.get('time', datetime.now().isoformat())
        event_source = event.get('source', 'Unknown')
        
        # TODO: Add support for additional event types in future versions
        
        # Extract information about the affected resource
        resource_arn = extract_resource_arn(event)
        
        # Extract information about who initiated the action
        initiator = extract_initiator(event)
        
        # Determine what action was performed
        action_description = extract_action(event)
        
        # Create a formatted notification message
        alert_message = create_notification_message(event_time, resource_arn, initiator, action_description, event)
        
        # Send the notification to the configured SNS topic
        send_notification(alert_message)
        
        # Return success response
        return {
            'statusCode': 200,
            'body': json.dumps('Successfully processed security event')
        }
    
    except Exception as e:
        # Log the full error for troubleshooting
        logger.error(f"Error processing event: {str(e)}")
        # Return error response
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing security event: {str(e)}')
        }

def extract_resource_arn(event):
    """
    Extract the ARN of the affected resource from the event.
    
    Different event types have different structures, so we need to handle
    each case separately. This function currently supports IAM, S3, and EC2
    security group events.
    """
    detail = event.get('detail', {})
    
    # Check if request parameters exist
    if 'requestParameters' in detail:
        req_params = detail['requestParameters']
        
        # IAM user events
        if 'userName' in req_params:
            return f"arn:aws:iam::{event.get('account', '')}:user/{req_params['userName']}"
        
        # S3 bucket events
        if 'bucketName' in req_params:
            return f"arn:aws:s3:::{req_params['bucketName']}"
        
        # EC2 security group events
        if 'groupId' in req_params:
            return f"arn:aws:ec2::{event.get('account', '')}:security-group/{req_params['groupId']}"
    
    # Fallback for unknown resource types
    # This could be improved in the future to handle more event types
    return f"arn:aws:{event.get('source', '').split('.')[0]}:{event.get('region', '')}:{event.get('account', '')}:resource/unknown"

def extract_initiator(event):
    """
    Extract the identity that initiated the action.
    
    AWS events can include different identity information depending on
    the service and action. This function tries to extract the most
    useful identifier available.
    """
    user_identity = event.get('detail', {}).get('userIdentity', {})
    
    # ARN is the most specific identifier
    if 'arn' in user_identity:
        return user_identity['arn']
    # Username is next best
    elif 'userName' in user_identity:
        return user_identity['userName']
    # Principal ID is less specific but still useful
    elif 'principalId' in user_identity:
        return user_identity['principalId']
    
    # If we can't find any identity information
    return "Unknown"

def extract_action(event):
    """
    Extract a human-readable description of the action that was performed.
    
    This function converts AWS API event names into more readable descriptions.
    For example, "CreateUser" becomes "Created User".
    """
    detail = event.get('detail', {})
    
    event_name = detail.get('eventName', 'Unknown')
    
    # Convert common AWS API event names to more readable descriptions
    if 'Create' in event_name:
        return f"Created {event_name.replace('Create', '')}"
    elif 'Update' in event_name:
        return f"Updated {event_name.replace('Update', '')}"
    elif 'Delete' in event_name:
        return f"Deleted {event_name.replace('Delete', '')}"
    elif 'Put' in event_name:
        return f"Modified {event_name.replace('Put', '')}"
    elif 'Authorize' in event_name:
        return f"Authorized {event_name.replace('Authorize', '')}"
    
    # If we can't convert it, just return the original event name
    return event_name

def create_notification_message(event_time, resource_arn, initiator, action, event):
    """
    Create a formatted notification message for the security alert.
    
    The message includes a subject line that summarizes the event,
    and a JSON body with detailed information about the event.
    """
    # Extract service name from the event source
    event_source = event.get('source', 'aws.unknown').replace('aws.', '')
    event_name = event.get('detail', {}).get('eventName', 'Unknown')
    
    # Create a structured message with a clear subject and detailed body
    message = {
        "Subject": f"AWS Security Alert: {event_source} - {event_name}",
        "Message": json.dumps({
            "Time": event_time,
            "ResourceARN": resource_arn,
            "Initiator": initiator,
            "Action": action,
            "EventDetails": event.get('detail', {})
        }, indent=2)
    }
    
    return message

def send_notification(message):
    """
    Send notification to the configured SNS topic.
    
    If the SNS topic ARN is not configured, log a warning and skip
    sending the notification.
    """
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN environment variable not set. Skipping notification.")
        return
    
    try:
        # Send the notification to the SNS topic
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=message["Subject"],
            Message=message["Message"]
        )
        logger.info(f"Notification sent successfully: {response}")
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
        # In a production environment, we might want to retry or alert on this failure
