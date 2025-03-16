#!/usr/bin/env python3
"""
Local test script for the AWS Security Monitor Lambda function.
This script simulates CloudWatch Events for testing the Lambda function locally.
"""

import json
import os
import sys
from security_monitor import lambda_handler

# Sample events for testing
SAMPLE_EVENTS = {
    "iam_user_creation": {
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
    },
    "iam_access_key_creation": {
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
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "userAgent": "AWS Console",
            "requestParameters": {
                "userName": "TestUser"
            },
            "responseElements": {
                "accessKey": {
                    "userName": "TestUser",
                    "accessKeyId": "AKIAEXAMPLE",
                    "status": "Active",
                    "createDate": "2023-01-01T12:00:00Z"
                }
            }
        }
    },
    "s3_bucket_policy_change": {
        "version": "0",
        "id": "12345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
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
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "userAgent": "AWS Console",
            "requestParameters": {
                "bucketName": "test-bucket",
                "policy": "[POLICY CONTENT]"
            },
            "responseElements": None
        }
    },
    "security_group_ingress_change": {
        "version": "0",
        "id": "12345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
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
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.1",
            "userAgent": "AWS Console",
            "requestParameters": {
                "groupId": "sg-12345",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [
                                    {
                                        "cidrIp": "0.0.0.0/0"
                                    }
                                ]
                            }
                        }
                    ]
                }
            },
            "responseElements": {
                "requestId": "12345678-1234-1234-1234-123456789012",
                "return": "true"
            }
        }
    }
}

def main():
    """Main function to run the local test."""
    # Set environment variables for local testing
    os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:security-alerts-topic"
    
    # Check if an event type was specified
    if len(sys.argv) > 1 and sys.argv[1] in SAMPLE_EVENTS:
        event_type = sys.argv[1]
    else:
        print("Available event types:")
        for event_type in SAMPLE_EVENTS:
            print(f"  - {event_type}")
        event_type = input("Select an event type to test: ")
        
        if event_type not in SAMPLE_EVENTS:
            print(f"Error: Unknown event type '{event_type}'")
            return
    
    # Get the selected event
    event = SAMPLE_EVENTS[event_type]
    
    print(f"Testing Lambda function with {event_type} event...")
    print("Event details:")
    print(json.dumps(event, indent=2))
    print("\n" + "-" * 80 + "\n")
    
    # Call the Lambda handler
    try:
        response = lambda_handler(event, {})
        print("Lambda response:")
        print(json.dumps(response, indent=2))
        
        if response["statusCode"] == 200:
            print("\nTest completed successfully!")
        else:
            print("\nTest completed with errors.")
    except Exception as e:
        print(f"Error during test: {str(e)}")

if __name__ == "__main__":
    main()
