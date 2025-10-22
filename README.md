# Python-Flask-API-for-AWS-resources-Compliance-Check

# Automated Infrastructure Compliance Checker 

This project provides an automated solution designed to verify your AWS cloud environment’s compliance with internal policies. It securely performs scheduled scans, integrates native AWS services, and follows robust, scalable DevOps architecture.

---

## Business Use Case Overview

Automates periodic security compliance checks for AWS resource naming, tag policies, configurations, and other standards. This tool fetches compliance rules from DynamoDB, scans target resources, stores reports in S3, sends alerts using SQS, logs all details to CloudWatch, and authenticates securely via IAM roles. Example covers simulated resource scanning—extend for production workloads.

---

## Prerequisites

- AWS DynamoDB (compliance rules table)
- AWS Secrets Manager (stores credentials or sensitive config)
- AWS S3 (for saving scan reports)
- AWS SQS (alerting on compliance failures)
- AWS CloudWatch (logging, monitoring, telemetry)
- IAM Role with permission for all above resources
- AWS EKS cluster (to schedule and run remote CronJob)
- Docker (locally for building, pushing containers)
- Python 3.9+ and pip

---

## Application Code

Create a file named `compliance_checker.py`:

```python
from flask import Flask, jsonify
import os
import logging
import datetime
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)

# --- Logging Setup (CloudWatch, Console) ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# For full integration, add a CloudWatch handler or manual log sending as required

# --- DynamoDB Configuration (Compliance Rules Store) ---
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
RULES_TABLE = os.environ.get("RULES_TABLE")

table = dynamodb.Table(RULES_TABLE)

# --- SQS Configuration (Alerts) ---
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
sqs = boto3.client('sqs', region_name=AWS_REGION)

# --- S3 Configuration (Reports) ---
S3_BUCKET = os.environ.get("S3_BUCKET")
s3 = boto3.client('s3', region_name=AWS_REGION)

# --- Secrets Manager Configuration ---
secrets_manager = boto3.client('secretsmanager', region_name=AWS_REGION)

@app.route('/scan')
def run_compliance_scan():
    """
    Run a simulated compliance scan.
    Steps:
      - Read compliance rules from DynamoDB.
      - Simulate scanning target resources.
      - Save a scan report to S3.
      - Send alert to SQS if non-compliant.
      - Retrieve extra config from Secrets Manager, if needed.
      - Log all operations.
    """
    try:
        # Retrieve compliance rules from DynamoDB
        response = table.scan()
        rules = response.get('Items', [])
        logger.info(f"Retrieved {len(rules)} compliance rule(s) from DynamoDB.")

        # Simulate scan (actual resource scanning code would go here)
        violations = len(rules) > 0

        # Create scan report
        report = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "violations": violations,
            "rules_checked": len(rules),
            "details": "Simulated scan: Policy violations detected." if violations else "All resources compliant."
        }

        # Save report to S3
        report_key = f"compliance-report-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        s3.put_object(Bucket=S3_BUCKET, Key=report_key, Body=str(report).encode())
        logger.info(f"Compliance report saved as {report_key} in S3.")

        # Send alert to SQS if there’s a violation
        if violations:
            sqs.send_message(QueueUrl=SQS_QUEUE_URL, MessageBody=f"Compliance violation detected at {report['timestamp']}")
            logger.info("Alert sent via SQS for compliance violation.")

        # Optionally retrieve extra config from Secrets Manager
        secret_name = "ExtraConfig"
        try:
            secret_response = secrets_manager.get_secret_value(SecretId=secret_name)
            extra_config = secret_response.get('SecretString')
            logger.info(f"Retrieved extra config '{secret_name}' from Secrets Manager.")
        except Exception as kv_ex:
            logger.warning(f"Could not retrieve secret '{secret_name}': {kv_ex}")
            extra_config = None

        return jsonify({"status": "Scan completed", "report": report, "extra_config": extra_config}), 200

    except Exception as e:
        logger.error("Error during compliance scan", exc_info=e)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # When run as a Flask application, listen on port 5000.
    app.run(host='0.0.0.0', port=5000)
```

---

## Unit Testing

Create a file named `test_compliance_checker.py`:

```python
import pytest
from compliance_checker import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_scan_endpoint(client):
    """Test that the /scan endpoint returns a 200 OK status."""
    response = client.get('/scan')
    assert response.status_code == 200
    json_data = response.get_json()
    assert "status" in json_data
```

Run with:
```bash
pytest test_compliance_checker.py
```

---

## Dockerization

Create a `requirements.txt` file:
```
flask
boto3
pytest
```

Then create a `Dockerfile`:
```
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY compliance_checker.py .
COPY test_compliance_checker.py .
EXPOSE 5000
CMD ["python", "compliance_checker.py"]
```

Build and push your Docker image:
```bash
docker build -t <your-ecr-repo>/compliance-checker:latest .
docker push <your-ecr-repo>/compliance-checker:latest
```

*Replace `<your-ecr-repo>` with your actual AWS ECR repo name.*

---

## Deploying to EKS as a CronJob

Create a Kubernetes manifest named `eks_cronjob.yaml`:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: compliance-checker-cron
spec:
  schedule: "0 2 * * *"  # Runs daily at 2 AM UTC
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: compliance-checker
        spec:
          containers:
          - name: compliance-checker
            image: <your-ecr-repo>/compliance-checker:latest
            env:
            - name: RULES_TABLE
              value: "<DYNAMODB_TABLE>"
            - name: S3_BUCKET
              value: "<S3_BUCKET>"
            - name: SQS_QUEUE_URL
              value: "<SQS_QUEUE_URL>"
            - name: AWS_REGION
              value: "<AWS_REGION>"
          restartPolicy: OnFailure
```

Deploy the CronJob to your EKS cluster:
```bash
kubectl apply -f eks_cronjob.yaml
```

---

## Summary of Steps

1. **Provision AWS Resources:** Set up DynamoDB, Secrets Manager, S3, SQS, CloudWatch, IAM Role, and EKS Cluster.
2. **Develop the Compliance Checker:** Python Flask application (`compliance_checker.py`) orchestrates scan, reporting, alerting.
3. **Add Unit Tests:** Pytest ensures `/scan` endpoint works as expected.
4. **Containerize the Application:** Add `requirements.txt` and `Dockerfile`, build/push to ECR.
5. **Deploy as EKS CronJob:** Use Kubernetes manifest for scheduling daily scans.
6. **Secure and Monitor:** Use IAM roles for authentication, CloudWatch for monitoring.

---

## Conclusion

This AWS-based solution automates infrastructure compliance checks with secure credential handling (IAM/Secrets), works across core AWS services, supports scalable scheduling via EKS, robust alerting through SQS, and centralized monitoring using CloudWatch.

For official AWS guidance, refer to the documentation for [`boto3`](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html), [DynamoDB](https://docs.aws.amazon.com/dynamodb/), [S3](https://docs.aws.amazon.com/s3/), [SQS](https://docs.aws.amazon.com/sqs/), [Secrets Manager](https://docs.aws.amazon.com/secretsmanager/), [EKS](https://docs.aws.amazon.com/eks/), and [CloudWatch](https://docs.aws.amazon.com/cloudwatch/).
