import os
import json
import yaml
import argparse
from datetime import datetime
import subprocess
from pathlib import Path

def validate_json_file(json_file_path):
    try:
        with open(json_file_path, 'r') as file:
            config_data = json.load(file)
        return config_data
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON validation error: {e}")

def generate_yaml_for_application(application, timestamp):
    # Set default values for optional parameters
    defaults = {
        "EnableLogging": "true",
        "LoggingPrefix": "",
        "IncludeCookies": "false"
    }
    
    # Merge defaults with application config
    app_config = {**defaults, **application}

    yaml_data = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"CloudFront deployment for {app_config['ApplicationName']}",
        "Parameters": {
            # Core parameters
            "ApplicationName": {"Type": "String", "Default": app_config["ApplicationName"]},
            "DomainNamePrefix": {"Type": "String", "Default": app_config["DomainNamePrefix"]},
            "DomainNameSuffix": {"Type": "String", "Default": app_config["DomainNameSuffix"]},
            "HostedDnsZoneId": {"Type": "String", "Default": app_config["HostedDnsZoneId"]},
            
            # CloudFront configuration
            "PriceClass": {
                "Type": "String",
                "Default": app_config["PriceClass"],
                "AllowedValues": ["PriceClass_100", "PriceClass_200", "PriceClass_All"]
            },
            "EnableIPv6": {
                "Type": "String",
                "Default": app_config["EnableIPv6"],
                "AllowedValues": ["true", "false"]
            },
            "HttpVersion": {
                "Type": "String",
                "Default": app_config["HttpVersion"],
                "AllowedValues": ["http1.1", "http2", "http3", "http2and3"]
            },
            "ViewerProtocolPolicy": {
                "Type": "String",
                "Default": app_config["ViewerProtocolPolicy"],
                "AllowedValues": ["allow-all", "https-only", "redirect-to-https"]
            },
            "Compress": {
                "Type": "String",
                "Default": app_config["Compress"],
                "AllowedValues": ["true", "false"]
            },
            "MinimumProtocolVersion": {
                "Type": "String",
                "Default": app_config["MinimumProtocolVersion"],
                "AllowedValues": [
                    "TLSv1.2_2021", "TLSv1.1_2016", "TLSv1.2_2018", 
                    "TLSv1.2_2019", "TLSv1_2016", "TLSv1"
                ]
            },
            
            # Logging parameters
            "EnableLogging": {
                "Type": "String",
                "Default": app_config["EnableLogging"],
                "AllowedValues": ["true", "false"]
            },
            "LoggingPrefix": {
                "Type": "String",
                "Default": app_config["LoggingPrefix"]
            },
            "IncludeCookies": {
                "Type": "String",
                "Default": app_config["IncludeCookies"],
                "AllowedValues": ["true", "false"]
            },
            
            # Failover and error handling
            "FailoverStatusCodes": {
                "Type": "CommaDelimitedList",
                "Default": app_config["FailoverStatusCodes"]
            },
            "FailoverQuantity": {
                "Type": "String",
                "Default": app_config["FailoverQuantity"]
            },
            "DefaultRootObject": {
                "Type": "String",
                "Default": app_config["DefaultRootObject"]
            },
            "ErrorPagePath": {
                "Type": "String",
                "Default": app_config["ErrorPagePath"]
            },
            "CustomErrorCode": {
                "Type": "String",
                "Default": app_config["CustomErrorCode"]
            },
            "CustomResponseCode": {
                "Type": "String",
                "Default": app_config["CustomResponseCode"]
            },
            "ErrorCachingMinTTL": {
                "Type": "String",
                "Default": app_config["ErrorCachingMinTTL"]
            },
            "EnableBackup": {
            "Type": "String",
            "Default": app_config["EnableBackup"],
            "AllowedValues": ["true", "false"]
            },
            # "EnableLogging": {
            #     "Type": "String",
            #     "Default": "false",
            #     "AllowedValues": ["true", "false"]
            # },

            # Geo-restriction
            "EnableGeoRestriction": {
                "Type": "String",
                "Default": app_config["EnableGeoRestriction"],
                "AllowedValues": ["true", "false"]
            },
            "GeoRestrictionType": {
                "Type": "String",
                "Default": app_config["GeoRestrictionType"],
                "AllowedValues": ["blacklist", "whitelist"]
            },
            "GeoRestrictionLocations": {
                "Type": "CommaDelimitedList",
                "Default": app_config["GeoRestrictionLocations"]
            },
            
            # Staging
            "Staging": {
                "Type": "String",
                "Default": app_config["Staging"],
                "AllowedValues": ["true", "false"]
            },
            "CreateBackupBucketParam": { 
                "Type": "String",
                "Default": "false",
                "AllowedValues":  ["true", "false"],
                "Description": "Whether to create the backup S3 bucket",
            }
        },
        "Conditions": {
            "IsLoggingEnabled": {"Fn::Equals": [{"Ref": "EnableLogging"}, "true"]},
            "HasLoggingPrefix": {"Fn::Not": [{"Fn::Equals": [{"Ref": "LoggingPrefix"}, ""]}]},
            "IsCompressionEnabled": {"Fn::Equals": [{"Ref": "Compress"}, "true"]},
            "EnableGeoRestrictionIsTrue": {"Fn::Equals": [{"Ref": "EnableGeoRestriction"}, "true"]},
            "IsStagingEnabled": {"Fn::Equals": [{"Ref": "Staging"}, "true"]},
            "CreateBackupBucket": { "Fn::Equals": [ { "Ref": "EnableBackup" }, "true" ] },
            "CreateLoggingBucket": { "Fn::Equals": [ { "Ref": "EnableLogging" }, "true" ] }},

        "Resources": {
            "S3Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}",
                    "AccessControl": "Private",
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{
                            "ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                        }]
                    },
                    "Tags": [{
                        "Key": "Name", 
                        "Value": f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}"
                    }]
                }
            },
            "CloudFrontOriginAccessIdentity": {
                "Type": "AWS::CloudFront::CloudFrontOriginAccessIdentity",
                "Properties": {
                    "CloudFrontOriginAccessIdentityConfig": {
                        "Comment": f"OAI for {app_config['ApplicationName']}"
                    }
                }
            },
            "S3BucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "S3Bucket"},
                    "PolicyDocument": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {
                                "CanonicalUser": {
                                    "Fn::GetAtt": ["CloudFrontOriginAccessIdentity", "S3CanonicalUserId"]
                                }
                            },
                            "Action": ["s3:GetObject"],
                            "Resource": {"Fn::Sub": "arn:aws:s3:::${S3Bucket}/*"}
                        }]
                    }
                }
            },
            "BackupS3Bucket": {
                "Type": "AWS::S3::Bucket",
                "Condition": "CreateBackupBucket",
                "Properties": {
                    "BucketName": { "Fn::Sub": "backup-${DomainNamePrefix}-${ApplicationName}.${DomainNameSuffix}" },
                    "AccessControl": "Private",
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{
                            "ServerSideEncryptionByDefault": { "SSEAlgorithm": "AES256" }
                        }]
                    },
                    "Tags": [{ "Key": "Name", "Value": { "Fn::Sub": "backup-${DomainNamePrefix}-${ApplicationName}" } }]
                }
            },
            "BackupS3BucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Condition": "CreateBackupBucket",
                "Properties": {
                    "Bucket": {"Ref": "BackupS3Bucket"},
                    "PolicyDocument": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {
                                "CanonicalUser": {
                                    "Fn::GetAtt": ["CloudFrontOriginAccessIdentity", "S3CanonicalUserId"]
                                }
                            },
                            "Action": ["s3:GetObject"],
                            "Resource": {"Fn::Sub": "arn:aws:s3:::${BackupS3Bucket}/*"}
                        }]
                    }
                }
            },
            "Certificate": {
            "Type": "AWS::CertificateManager::Certificate",
            "Properties": {
                "DomainName": f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}",
                "SubjectAlternativeNames": {
                "Fn::If": [
                    "CreateBackupBucket",
                    [f"backup-{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}"],
                    []
                ]
                },
                "ValidationMethod": "DNS",
                "DomainValidationOptions": {
                "Fn::If": [
                    "CreateBackupBucket",
                    [
                    {
                        "DomainName": f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}",
                        "HostedZoneId": app_config["HostedDnsZoneId"]
                    },
                    {
                        "DomainName": f"backup-{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}",
                        "HostedZoneId": app_config["HostedDnsZoneId"]
                    }
                    ],
                    [
                    {
                        "DomainName": f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}",
                        "HostedZoneId": app_config["HostedDnsZoneId"]
                    }
                    ]
                ]
                }
            }
            },
            "CloudFrontLogsBucket": {
                "Type": "AWS::S3::Bucket",
                "Condition": "CreateLoggingBucket",
                "Properties": {
                    "BucketName": { "Fn::Sub": "${DomainNamePrefix}-${ApplicationName}-logs" },
                    "OwnershipControls": {
                        "Rules": [{ "ObjectOwnership": "BucketOwnerPreferred" }]
                    },
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": "true",
                        "BlockPublicPolicy": "true",
                        "IgnorePublicAcls": "true",
                        "RestrictPublicBuckets": "true"
                    },
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{
                            "ServerSideEncryptionByDefault": { "SSEAlgorithm": "AES256" }
                        }]
                    },
                    "Tags": [{ "Key": "Name", "Value": { "Fn::Sub": "${DomainNamePrefix}-${ApplicationName}-logs" } }]
                }
            },
            "CloudFrontDistribution": {
                "Type": "AWS::CloudFront::Distribution",
                "DependsOn": ["S3Bucket", "Certificate"],
                "Properties": {
                    "DistributionConfig": {
                        "Aliases": [
                            f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}"
                        ],
                        "Comment": f"CloudFront distribution for {app_config['ApplicationName']}",
                        "DefaultCacheBehavior": {
                            "TargetOriginId": f"primary-origin-{app_config['ApplicationName']}",
                            "ViewerProtocolPolicy": {"Ref": "ViewerProtocolPolicy"},
                            "Compress": {"Fn::If": ["IsCompressionEnabled", "true", "false"]},
                            "ForwardedValues": {"QueryString": False},
                            "DefaultTTL": 86400,
                            "MinTTL": 0,
                            "MaxTTL": 31536000,
                            "AllowedMethods": ["GET", "HEAD"],
                            "CachedMethods": ["GET", "HEAD"]
                        },
                        "DefaultRootObject": {"Ref": "DefaultRootObject"},
                        "Enabled": True,
                        "HttpVersion": {"Ref": "HttpVersion"},
                        "IPV6Enabled": {"Ref": "EnableIPv6"},
                        "Logging": {
                            "Fn::If": [
                                "CreateLoggingBucket",
                                {
                                    "Bucket": { "Fn::GetAtt": ["CloudFrontLogsBucket", "DomainName"] },
                                    "IncludeCookies": { "Ref": "IncludeCookies" },
                                    "Prefix": { "Fn::If": ["HasLoggingPrefix", { "Ref": "LoggingPrefix" }, {"Fn::Sub": f"{app_config['ApplicationName']}/"}]}
                                },
                                { "Ref": "AWS::NoValue" }
                            ]
                        },

                        "Origins": {
                        "Fn::If": [
                            "CreateBackupBucket",
                            [
                            {
                                "Id": f"primary-origin-{app_config['ApplicationName']}",
                                "DomainName": {"Fn::GetAtt": ["S3Bucket", "DomainName"]},
                                "S3OriginConfig": {
                                "OriginAccessIdentity": {
                                    "Fn::Sub": "origin-access-identity/cloudfront/${CloudFrontOriginAccessIdentity}"
                                }
                                }
                            },
                            {
                                "Id": f"backup-origin-{app_config['ApplicationName']}",
                                "DomainName": {"Fn::GetAtt": ["BackupS3Bucket", "DomainName"]},
                                "S3OriginConfig": {
                                "OriginAccessIdentity": {
                                    "Fn::Sub": "origin-access-identity/cloudfront/${CloudFrontOriginAccessIdentity}"
                                }
                                }
                            }
                            ],
                            [
                            {
                                "Id": f"primary-origin-{app_config['ApplicationName']}",
                                "DomainName": {"Fn::GetAtt": ["S3Bucket", "DomainName"]},
                                "S3OriginConfig": {
                                "OriginAccessIdentity": {
                                    "Fn::Sub": "origin-access-identity/cloudfront/${CloudFrontOriginAccessIdentity}"
                                }
                                }
                            }
                            ]
                        ]
                        },
                        "OriginGroups": {
                        "Fn::If": [
                            "CreateBackupBucket",
                            {
                            "Items": [{
                                "Id": f"failover-group-{app_config['ApplicationName']}",
                                "FailoverCriteria": {
                                "StatusCodes": {
                                    "Items": {"Ref": "FailoverStatusCodes"},
                                    "Quantity": {"Ref": "FailoverQuantity"}
                                }
                                },
                                "Members": {
                                "Items": [
                                    {"OriginId": f"primary-origin-{app_config['ApplicationName']}"},
                                    {"OriginId": f"backup-origin-{app_config['ApplicationName']}"}
                                ],
                                "Quantity": 2
                                }
                            }],
                            "Quantity": 1
                            },
                            {"Ref": "AWS::NoValue"}
                        ]
                        },
                        "PriceClass": {"Ref": "PriceClass"},
                        "Restrictions": {
                            "GeoRestriction": {
                                "RestrictionType": {
                                    "Fn::If": [
                                        "EnableGeoRestrictionIsTrue",
                                        {"Ref": "GeoRestrictionType"},
                                        "none"
                                    ]
                                },
                                "Locations": {
                                    "Fn::If": [
                                        "EnableGeoRestrictionIsTrue",
                                        {"Ref": "GeoRestrictionLocations"},
                                        []
                                    ]
                                }
                            }
                        },
                        "ViewerCertificate": {
                            "AcmCertificateArn": {"Ref": "Certificate"},
                            "MinimumProtocolVersion": {"Ref": "MinimumProtocolVersion"},
                            "SslSupportMethod": "sni-only"
                        },
                        "CustomErrorResponses": [{
                            "ErrorCode": {"Ref": "CustomErrorCode"},
                            "ResponseCode": {"Ref": "CustomResponseCode"},
                            "ResponsePagePath": {"Ref": "ErrorPagePath"},
                            "ErrorCachingMinTTL": {"Ref": "ErrorCachingMinTTL"}
                        }]
                    },
                    "Tags": [{
                        "Key": "Name",
                        "Value": f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}"
                    }]
                }
            },
            "CloudFrontLogsBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Condition": "CreateLoggingBucket",
                "Properties": {
                    "Bucket": {"Ref": "CloudFrontLogsBucket"},
                    "PolicyDocument": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudfront.amazonaws.com"},
                            "Action": "s3:PutObject",
                            "Resource": {"Fn::Sub": "arn:aws:s3:::${CloudFrontLogsBucket}/*"},
                            "Condition": {
                                "StringEquals": {
                                    "AWS:SourceArn": {
                                        "Fn::Sub": "arn:aws:cloudfront::${AWS::AccountId}:distribution/${CloudFrontDistribution}"
                                    }
                                }
                            }
                        }]
                    }
                }
            },
            "DNSRecord": {
                "Type": "AWS::Route53::RecordSetGroup",
                "DependsOn": ["CloudFrontDistribution"],
                "Properties": {
                    "HostedZoneId": app_config["HostedDnsZoneId"],
                    "RecordSets": [{
                        "Name": f"{app_config['DomainNamePrefix']}-{app_config['ApplicationName']}.{app_config['DomainNameSuffix']}",
                        "Type": "A",
                        "AliasTarget": {
                            "HostedZoneId": "Z2FDTNDATAQYW2",
                            "DNSName": {"Fn::GetAtt": ["CloudFrontDistribution", "DomainName"]}
                        }
                    }]
                }
            }
        },
        "Outputs": {
            "CloudFrontDomain": {
                "Description": "CloudFront Distribution Domain",
                "Value": {"Fn::GetAtt": ["CloudFrontDistribution", "DomainName"]}
            },
            "S3BucketName": {
                "Description": "Primary S3 Bucket Name",
                "Value": {"Ref": "S3Bucket"}
            }
        }
    }
    # Add CacheBehaviors if specified in the config
    if 'CacheBehaviors' in app_config and app_config['CacheBehaviors']:
        yaml_data['Resources']['CloudFrontDistribution']['Properties']['DistributionConfig']['CacheBehaviors'] = [
            {
                "PathPattern": behavior["PathPattern"],
                "TargetOriginId": behavior["TargetOriginId"],
                "ViewerProtocolPolicy": behavior["ViewerProtocolPolicy"],
                "AllowedMethods": behavior["AllowedMethods"],
                "CachedMethods": behavior["CachedMethods"],
                "Compress": behavior["Compress"],
                "DefaultTTL": behavior["DefaultTTL"],
                "MaxTTL": behavior["MaxTTL"],
                "MinTTL": behavior["MinTTL"],
                "ForwardedValues": {
                    "QueryString": behavior["ForwardedValues"]["QueryString"]
                }
            }
            for behavior in app_config['CacheBehaviors']
        ]

    # Create output directory
    output_dir = Path(f"output/output_{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save YAML file
    yaml_filename = output_dir / f"{app_config['ApplicationName']}.yml"
    with open(yaml_filename, 'w') as file:
        yaml.dump(yaml_data, file, default_flow_style=False)

    return str(yaml_filename)

def deploy_cloudformation_stack(yaml_file):
    stack_name = os.path.basename(yaml_file).split('.')[0]
    cmd = [
        "aws", "cloudformation", "create-stack",
        "--stack-name", stack_name,
        "--template-body", f"file://{yaml_file}",
        "--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM",
        "--region", "us-east-1"
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print(f"Stack {stack_name} deployed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error deploying stack {stack_name}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Create and deploy CloudFormation templates for CloudFront distributions.")
    parser.add_argument('--config', type=str, required=True, help="Path to JSON config file")
    parser.add_argument('--deploy', action='store_true', help="Deploy stacks to AWS")
    args = parser.parse_args()

    config_data = validate_json_file(args.config)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    yaml_files = []

    for app_key, app_value in config_data['applications'].items():
        yaml_file = generate_yaml_for_application(app_value, timestamp)
        print(f"Generated YAML for {app_value['ApplicationName']}: {yaml_file}")
        yaml_files.append(yaml_file)

    if args.deploy:
        for yaml_file in yaml_files:
            deploy_cloudformation_stack(yaml_file)
    else:
        print("Templates created. Use --deploy to deploy to AWS.")

if __name__ == "__main__":
    main()