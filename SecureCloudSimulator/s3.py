import boto3
import argparse
import json
import datetime
import sys
import botocore
import time
import click
 
 
from botocore.exceptions import ClientError
from pyboto3 import *
 
 
# ------------------------------------------------------------------------------------------------------------------------
def s3_client():
    """
        Function: get s3 client
         Purpose: get s3 client
        :returns: s3
    """
    session = boto3.session.Session()
    client = session.client('s3')
    """ :type : pyboto3.s3 """
    return client



def list_s3_buckets():
    """
        Function: list_s3_buckets
         Purpose: Get the list of s3 buckets
        :returns: s3 buckets in your aws account
    """
    client = s3_client()
    buckets_response = client.list_buckets()
 
    # check buckets list returned successfully
    if buckets_response['ResponseMetadata']['HTTPStatusCode'] == 200:
        for s3_buckets in buckets_response['Buckets']:
            print(f" *** Bucket Name: {s3_buckets['Name']} - Created on {s3_buckets['CreationDate']} \n")
    else:
        print(f" *** Failed while trying to get buckets list from your account")


def s3_create_bucket(bucket_name):
    """
        function: s3_create_bucket - create s3 bucket
           :args: s3 bucket name
        :returns: bucket
    """
 
    # fetch the region
    session = boto3.session.Session()
    current_region = session.region_name
 
    # get the client
    client = s3_client()
 
    print(f" *** You are in {current_region} AWS region..\n Bucket name passed is - {bucket_name}")
 
    s3_bucket_create_response = client.create_bucket(Bucket=bucket_name,
                                                          CreateBucketConfiguration={
                                                              'LocationConstraint': current_region})
 
    print(f" *** Response when creating bucket - {s3_bucket_create_response} ")
    return s3_bucket_create_response


# ------------------------------------------------------------------------------------------------------------------------
def s3_create_bucket_policy(s3_bucket_name):
    """
        function: s3_create_bucket_policy - Apply bucket policy
           :args: none
        :returns: none
           Notes: For test purpose let us allow all the actions, Need to change later.
    """
    resource = f"arn:aws:s3:::{s3_bucket_name}/*"
    s3_bucket_policy = {"Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AddPerm",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": resource,
                                "Condition": {
                                    "IpAddress": {"aws:SourceIp": ""}
                                }
 
                            }
                        ]}
 
    # prepare policy to be applied to AWS as Json
    policy = json.dumps(s3_bucket_policy)
 
    # apply policy
    s3_bucket_policy_response = s3_client().put_bucket_policy(Bucket=s3_bucket_name,
                                                              Policy=policy)
 
    # print response
    print(f" ** Response when applying policy to {s3_bucket_name} is {s3_bucket_policy_response} ")
    return s3_bucket_policy_response




def s3_list_bucket_policy(s3_bucket_name):
    """
        function: s3_list_bucket_policy - list the bucket policy
           :args: none
        :returns: none
    """
    s3_list_bucket_policy_response = s3_client().get_bucket_policy(Bucket=s3_bucket_name)
    print(s3_list_bucket_policy_response)



def s3_version_bucket_files(s3_bucket_name):
    client = s3_client()
    version_bucket_response = client.put_bucket_versioning(Bucket=s3_bucket_name,
                                                           VersioningConfiguration={'Status': 'Enabled'})
    # check apply bucket response..
    if version_bucket_response['ResponseMetadata']['HTTPStatusCode'] == 204:
        print(f" *** Successfully applied Versioning to {s3_bucket_name}")
    else:
        print(f" *** Failed while applying Versioning to bucket")


def s3_upload_small_files(inp_file_name, s3_bucket_name, inp_file_key, content_type):
    client = s3_client()
    upload_file_response = client.put_object(Body=inp_file_name,
                                             Bucket=s3_bucket_name,
                                             Key=inp_file_key,
                                             ContentType=content_type)
    print(f" ** Response - {upload_file_response}")



if __name__ == '__main__':
    list_s3_buckets()
    bucket_name = f"flask-small-file-uploads"
    s3_bucket = s3_create_bucket(bucket_name)
    s3_apply_bucket_policy = s3_create_bucket_policy(bucket_name)
    s3_show_bucket_policy = s3_list_bucket_policy(bucket_name)
    s3_show_bucket_response = s3_version_bucket_files(bucket_name)
    list_s3_buckets()