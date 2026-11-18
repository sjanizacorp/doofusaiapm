"""Read-only Cloud Storage permission checks for the authenticated ADC principal."""
import re

from gcs import BUCKET, CollectionError, access_token, fetch_google, project_id

PERMISSION = re.compile(r"storage\.(buckets|objects|managedFolders)\.[a-zA-Z][a-zA-Z0-9]{0,79}")
PROJECT_ONLY = {"storage.buckets.list", "storage.buckets.create"}
USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
BUCKET_API = "https://storage.googleapis.com/storage/v1/b"


def validate(bucket, project_number, permissions, quota_project):
    if (BUCKET.fullmatch(bucket) is None or not isinstance(project_number, str)
            or re.fullmatch(r"[0-9]{1,20}", project_number) is None):
        raise CollectionError("Use a bucket with source-backed Google project identity.")
    if (not 1 <= len(permissions) <= 30 or len(set(permissions)) != len(permissions)
            or any(PERMISSION.fullmatch(item) is None or item in PROJECT_ONLY for item in permissions)):
        raise CollectionError("Use one to 30 distinct bucket-scope IAM permission names.")
    if quota_project:
        project_id(quota_project)


def bucket_revision(fetch, endpoint, bucket, project_number, token, quota_project):
    metadata = fetch(endpoint, {"fields": "name,projectNumber,metageneration"}, token, quota_project,
                     "Cloud Storage bucket identity")
    revision = metadata.get("metageneration") if isinstance(metadata, dict) else None
    if (not isinstance(metadata, dict) or metadata.get("name") != bucket
            or metadata.get("projectNumber") != project_number
            or not isinstance(revision, str) or re.fullmatch(r"[0-9]{1,20}", revision) is None):
        raise CollectionError("Cloud Storage bucket identity did not match the inventoried project.")
    return revision


def evaluate(bucket, project_number, permissions, quota_project=None, *, credential=access_token,
             fetch=fetch_google):
    validate(bucket, project_number, permissions, quota_project)
    token = credential()
    identity = fetch(USERINFO, None, token, None, "Google caller identity")
    subject = identity.get("sub") if isinstance(identity, dict) else None
    if not isinstance(subject, str) or re.fullmatch(r"[0-9]{1,64}", subject) is None:
        raise CollectionError("Could not verify the Google caller identity from the active credential.")
    endpoint = f"{BUCKET_API}/{bucket}"
    arguments = (fetch, endpoint, bucket, project_number, token, quota_project)
    before = bucket_revision(*arguments)
    result = fetch(endpoint + "/iam/testPermissions", [("permissions", permission) for permission in permissions],
                   token, quota_project, "Cloud Storage caller permission test")
    if not isinstance(result, dict) or result.get("kind") != "storage#testIamPermissionsResponse":
        raise CollectionError("Google returned a malformed permission test response.")
    allowed = result.get("permissions", [])
    if (not isinstance(allowed, list) or any(not isinstance(item, str) or item not in permissions
                                             for item in allowed) or len(set(allowed)) != len(allowed)):
        raise CollectionError("Google returned permissions outside the requested set.")
    if bucket_revision(*arguments) != before:
        raise CollectionError("Bucket metadata changed during the test. Retry the review.")
    return "google-sub:" + subject, [
        {"action": permission, "decision": "allowed" if permission in allowed else "denied"}
        for permission in permissions
    ]


def troubleshoot(bucket, project_number, permissions, quota_project=None, *, principal,
                 credential=access_token, fetch=fetch_google, receive_time=None):
    """Record the provider's IAM assessment for a named Google account."""
    validate(bucket, project_number, permissions, quota_project)
    if (len(principal) > 254 or re.fullmatch(
            r"[A-Za-z0-9._%+!-]+@[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+", principal) is None):
        raise CollectionError("Enter a Google user or service account email address.")
    token = credential()
    arguments = (fetch, f"{BUCKET_API}/{bucket}", bucket, project_number, token, quota_project)
    before = bucket_revision(*arguments)
    resource = f"//storage.googleapis.com/projects/_/buckets/{bucket}"
    decisions = []
    for permission in permissions:
        access_tuple = {"principal": principal, "fullResourceName": resource, "permission": permission}
        result = fetch("https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot", None,
                       token, quota_project, "Google IAM Policy Troubleshooter",
                       payload={"accessTuple": access_tuple | (
                           {"conditionContext": {"request": {"receiveTime": receive_time}}}
                           if receive_time else {})})
        returned = result.get("accessTuple") if isinstance(result, dict) else None
        state = result.get("overallAccessState") if isinstance(result, dict) else None
        if (not isinstance(returned, dict) or any(returned.get(key) != value for key, value in access_tuple.items())
                or state not in ("CAN_ACCESS", "CANNOT_ACCESS", "UNKNOWN_INFO",
                                 "UNKNOWN_CONDITIONAL", "OVERALL_ACCESS_STATE_UNSPECIFIED", None)):
            raise CollectionError("Google returned an invalid or mismatched IAM evaluation.")
        decision = {"action": permission, "provider_state": state, "decision": {
            "CAN_ACCESS": "allowed", "CANNOT_ACCESS": "denied",
        }.get(state, "indeterminate")}
        if receive_time:
            decision["condition_receive_time"] = receive_time
        decisions.append(decision)
    if bucket_revision(*arguments) != before:
        raise CollectionError("Bucket metadata changed during the test. Retry the review.")
    return "google-account:" + principal, decisions
