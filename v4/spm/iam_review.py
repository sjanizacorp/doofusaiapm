"""Read-only AWS policy-simulation evidence for explicit same-account access reviews."""
import re

from aws_inventory import ARN, cli
from gcs import CollectionError

ACTION = re.compile(r"[a-z][a-z0-9-]{0,32}:[A-Za-z][A-Za-z0-9]{0,80}")
DECISIONS = {"allowed", "explicitDeny", "implicitDeny"}
def request_scope(principal, resource, actions):
    role = ARN.fullmatch(principal)
    target = ARN.fullmatch(resource)
    if not role or role[2] != "iam" or not role[5].startswith("role/"):
        raise CollectionError("The inventory resource is not an AWS IAM role.")
    if not target or target[1] != role[1] or (target[4] and target[4] != role[4]):
        raise CollectionError("Use one exact resource ARN in the selected AWS partition and account.")
    if not target[4] and (target[2] != "s3" or target[3]):
        raise CollectionError("Only selected same-account resources or inventoried S3 buckets are supported.")
    if (not 1 <= len(actions) <= 30 or any(ACTION.fullmatch(action) is None for action in actions)
            or len({action.lower() for action in actions}) != len(actions)):
        raise CollectionError("Supply one to 30 distinct AWS action names without wildcards.")
    bucket = target[5].split("/", 1)[0] if not target[4] else None
    return role[4], f"arn:{role[1]}:s3:::{bucket}" if bucket else None


def missing_context(entry):
    keys = entry.get("MissingContextValues", [])
    if not isinstance(keys, list) or len(keys) > 100 or any(
        not isinstance(key, str) or not 1 <= len(key) <= 256 or not key.isprintable() for key in keys
    ):
        raise CollectionError("AWS returned malformed missing-context evidence.")
    return set(keys)


def boolean_detail(entry, section, field):
    if section not in entry:
        return None
    detail = entry[section]
    value = detail.get(field) if isinstance(detail, dict) else None
    if type(value) is not bool:
        raise CollectionError("AWS returned malformed policy constraint evidence.")
    return value


def evaluate(region, principal, resource, actions, *, invoke=cli):
    account, _ = request_scope(principal, resource, actions)
    caller = invoke(region, "sts", "get-caller-identity")
    if caller.get("Account") != account:
        raise CollectionError("The active AWS CLI identity is in another account.")
    response = invoke(
        region, "iam", "simulate-principal-policy", "--no-paginate",
        "--policy-source-arn", principal, "--resource-arns", resource, "--action-names", *actions,
    )
    if response.get("IsTruncated") is True or response.get("Marker") or response.get("NextToken"):
        raise CollectionError("AWS simulation was incomplete. Review a smaller set of actions.")
    evaluations = response.get("EvaluationResults")
    if not isinstance(evaluations, list) or len(evaluations) != len(actions):
        raise CollectionError("AWS did not return one simulation result per requested action.")
    requested = {action.lower(): action for action in actions}
    outcomes = {}
    for entry in evaluations:
        if not isinstance(entry, dict):
            raise CollectionError("AWS returned malformed simulation evidence.")
        reported_action = entry.get("EvalActionName")
        key = reported_action.lower() if isinstance(reported_action, str) else ""
        if key not in requested or key in outcomes:
            raise CollectionError("AWS returned an unexpected or duplicate action result.")
        resource_results = entry.get("ResourceSpecificResults", [])
        if not isinstance(resource_results, list) or len(resource_results) > 1:
            raise CollectionError("AWS returned ambiguous resource evidence.")
        specific = None
        if resource_results:
            specific = resource_results[0]
            if not isinstance(specific, dict) or specific.get("EvalResourceName") != resource:
                raise CollectionError("AWS returned a different resource from the requested ARN.")
        elif entry.get("EvalResourceName") != resource:
            raise CollectionError("AWS did not confirm the requested resource.")
        decision = specific.get("EvalResourceDecision") if specific else entry.get("EvalDecision")
        if not isinstance(decision, str) or decision not in DECISIONS:
            raise CollectionError("AWS returned an unsupported decision.")
        # Keep missing identity context from both levels when AWS supplies an aggregate.
        missing = missing_context(entry) | (missing_context(specific) if specific else set())
        boundary = boolean_detail(specific or {}, "PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary")
        if boundary is None:
            boundary = boolean_detail(entry, "PermissionsBoundaryDecisionDetail", "AllowedByPermissionsBoundary")
        organizations = boolean_detail(specific or {}, "OrganizationsDecisionDetail", "AllowedByOrganizations")
        if organizations is None:
            organizations = boolean_detail(entry, "OrganizationsDecisionDetail", "AllowedByOrganizations")
        outcomes[key] = {
            "action": requested[key],
            "decision": "indeterminate" if missing or (
                decision == "allowed" and (boundary is False or organizations is False)
            ) else decision,
            "reported_decision": decision, "missing_context": sorted(missing),
            "permissions_boundary_allows": boundary, "organizations_allows": organizations,
        }
    return [outcomes[action.lower()] for action in actions]
