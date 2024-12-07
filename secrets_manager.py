import boto3
import json
import os
from botocore.exceptions import ClientError

def get_secrets(secret_name="gnosis-secrets", region_name="us-east-1"):        
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        return json.loads(get_secret_value_response['SecretString'])
    except ClientError as e:
        raise e

def get_service_secrets(service_name):

    # For prod use 
    '''
    secrets = get_secrets()
    return secrets.get(service_name, {})
    '''

    # For local testing with AWS RDS
    if service_name == 'gnosis-user-registration':
        return {
            "MYSQL_USER": "admin",
            "MYSQL_PASSWORD_USERS": "IbU1Y5pFflqrrzduf7oC",
            "MYSQL_HOST": "users-db.cffwkffbiore.us-east-1.rds.amazonaws.com",
            "MYSQL_PORT": "3306",
            "MYSQL_DATABASE": "user_db",
            "PORT": "5000",
            "JWT_SECRET_KEY": "BzR9J-Gn7-eiCq6PDP_yriiq_wRQ"
        }
    return {}