"""AWS Lambda handler for Amazon Bedrock Managed Agent Action Group.

Fulfills the 'get_current_assessment_evidence' tool call by querying
the session context store and returning sanitized evidence to Bedrock.
"""
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# In production, context is stored in DynamoDB or ElastiCache keyed by session_id
SESSION_CACHE = {}


def lambda_handler(event, context):
    logger.info("Received event from Bedrock Agent: %s", json.dumps(event))

    action_group = event.get("actionGroup", "")
    api_path = event.get("apiPath", "")
    http_method = event.get("httpMethod", "")
    session_id = event.get("sessionId", "")

    # Parse request parameters / body
    request_body = event.get("requestBody", {}).get("content", {}).get("application/json", {})
    body_data = {}
    if isinstance(request_body, str):
        try:
            body_data = json.loads(request_body)
        except Exception:
            body_data = {}
    elif isinstance(request_body, dict):
        body_data = request_body

    target_session = body_data.get("session_id") or session_id

    # Retrieve session-bound evidence
    evidence = SESSION_CACHE.get(target_session, {
        "assessment_id": f"assess-{session_id[:8] if session_id else 'default'}",
        "package_name": "samplepkg",
        "to_version": "1.0.1",
        "official_verdict": "PASS",
        "reason_codes": ["STARTUP_POLICY_SATISFIED"],
        "hook_diffs": [],
        "untrusted_text": {
            "content": "Safe synthetic sample package. Not imported."
        }
    })

    response_body = {
        "application/json": {
            "body": json.dumps(evidence)
        }
    }

    action_response = {
        "actionGroup": action_group,
        "apiPath": api_path,
        "httpMethod": http_method,
        "httpStatusCode": 200,
        "responseBody": response_body
    }

    return {
        "messageVersion": "1.0",
        "response": action_response
    }
