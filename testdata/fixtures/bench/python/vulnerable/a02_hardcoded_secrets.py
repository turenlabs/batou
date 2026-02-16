# Source: CWE-798 - Hardcoded credentials in application code
# Expected: BATOU-SEC-001 (Hardcoded Password), BATOU-SEC-002 (API Key), BATOU-SEC-004 (Connection String)
# OWASP: A02:2021 - Cryptographic Failures (Hardcoded Secrets)

import boto3
import pymysql

DATABASE_PASSWORD = "p@ssw0rd123!"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_KEY = "sk-proj-abc123def456ghi789"

def get_db_connection():
    conn_string = "mysql://admin:p@ssw0rd123!@db.internal.example.com:3306/production"
    return pymysql.connect(
        host='db.internal.example.com',
        user='admin',
        password=DATABASE_PASSWORD,
        database='production'
    )

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )

def call_external_api(endpoint: str):
    import requests
    headers = {'Authorization': f'Bearer {API_KEY}'}
    return requests.get(endpoint, headers=headers)
