"""Read-only AWS AI inventory and supported IAM Access Analyzer metadata."""
import json
import re
import subprocess
import tempfile

from gcs import BUCKET, CollectionError

REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]")
ACCOUNT = re.compile(r"[0-9]{12}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}")
AGENT_ID = re.compile(r"[A-Za-z0-9]{1,32}")
ARN = re.compile(r"arn:(aws(?:-[a-z0-9-]+)?):([a-z0-9-]+):([a-z0-9-]*):([0-9]{0,12}):([A-Za-z0-9_./+=,@:-]+)")
MAX_RESPONSE = 2 * 1024 * 1024
SCHEMA = """
CREATE TABLE aws_scope_analyzers (
  project TEXT NOT NULL, scope TEXT NOT NULL, arn TEXT NOT NULL, PRIMARY KEY(project,scope)
);
"""


def parameters(account, region):
    if ACCOUNT.fullmatch(account) is None or REGION.fullmatch(region) is None:
        raise CollectionError("Use a 12-digit AWS account and a valid region.")


def cli(region, service, action, *arguments):
    command = ["aws", "--region", region, "--output", "json", "--no-cli-pager",
               "--cli-connect-timeout", "5", "--cli-read-timeout", "12",
               service, action, *arguments]
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                           check=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            raise CollectionError(f"AWS {service} {action} failed. Check credentials, scope and region.") from None
        output.seek(0)
        raw = output.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise CollectionError(f"AWS {service} {action} exceeded the response limit.")
    try:
        result = json.loads(raw)
    except (ValueError, RecursionError):
        raise CollectionError(f"AWS {service} {action} returned invalid JSON.") from None
    if not isinstance(result, dict):
        raise CollectionError(f"AWS {service} {action} returned a malformed object.")
    return result


def objects(record, key):
    value = record.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CollectionError(f"AWS returned malformed {key}.")
    return value


def page(call, service, action, key, extra=(), limit=200):
    result, seen, token = [], set(), None
    for _ in range(20):
        args = ("--starting-token", token) if token else ()
        reply = call(service, action, "--max-items", "100", *extra, *args)
        result.extend(objects(reply, key))
        if len(result) > limit:
            raise CollectionError(f"AWS {key} exceeds the qualification scope limit ({limit}).")
        token = reply.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not 1 <= len(token) <= 4096 or token in seen:
            raise CollectionError(f"AWS {key} pagination did not advance.")
        seen.add(token)
    raise CollectionError(f"AWS {key} inventory exceeds the page limit.")


def scalar(value, pattern, label):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CollectionError(f"AWS returned an invalid {label}.")
    return value


def discover(account, region, analyzer=None, *, invoke=cli):
    parameters(account, region)

    def call(service, action, *args):
        return invoke(region, service, action, *args)

    caller = call("sts", "get-caller-identity")
    if caller.get("Account") != account:
        raise CollectionError("The active AWS CLI identity is in another account.")
    identity = ARN.fullmatch(caller.get("Arn", "")) if isinstance(caller.get("Arn"), str) else None
    if identity is None or identity[4] != account:
        raise CollectionError("AWS returned an invalid caller identity.")
    prefix = "arn:" + identity[1]
    nodes, edges, model_keys, configurations = {}, set(), {}, {}

    def node(key, kind, name):
        nodes.setdefault(key, {"kind": kind, "name": name})

    def role(origin, value):
        if not isinstance(value, str):
            return
        match = ARN.fullmatch(value)
        if match and match[1] == identity[1] and match[2] == "iam" and match[4] == account and match[5].startswith("role/"):
            node(value, "identity", match[5])
            edges.add((origin, value, "uses_identity"))

    for listed in page(call, "sagemaker", "list-models", "Models"):
        name = scalar(listed.get("ModelName"), NAME, "model name")
        key = f"{prefix}:sagemaker:{region}:{account}:model/{name}"
        model_keys[name] = key
        model = call("sagemaker", "describe-model", "--model-name", name)
        if model.get("ModelArn") != key:
            raise CollectionError("AWS returned an unexpected SageMaker model.")
        node(key, "model", name)
        role(key, model.get("ExecutionRoleArn"))
        vpc = model.get("VpcConfig")
        if vpc is not None:
            if not isinstance(vpc, dict):
                raise CollectionError("AWS returned malformed SageMaker VPC configuration.")
            for field, resource, pattern, relation in (
                ("Subnets", "subnet", r"subnet-[a-f0-9]{8,17}", "uses_subnet"),
                ("SecurityGroupIds", "security-group", r"sg-[a-f0-9]{8,17}", "uses_security_group"),
            ):
                identifiers = vpc.get(field)
                if not isinstance(identifiers, list) or not 1 <= len(identifiers) <= 16:
                    raise CollectionError("AWS returned malformed SageMaker network attachments.")
                for value in identifiers:
                    scalar(value, re.compile(pattern), "SageMaker network attachment")
                    network = f"{prefix}:ec2:{region}:{account}:{resource}/{value}"
                    node(network, "network", value)
                    edges.add((key, network, relation))
        containers = objects(model, "Containers")
        if isinstance(model.get("PrimaryContainer"), dict):
            containers = [model["PrimaryContainer"], *containers]
        for container in containers:
            image = container.get("Image")
            if isinstance(image, str):
                registry = re.fullmatch(
                    r"([0-9]{12})[.]dkr[.]ecr[.]([a-z0-9-]+)[.]amazonaws[.]com(?:[.]cn)?/"
                    r"([a-z0-9]+(?:[._/-][a-z0-9]+)*)(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})?", image,
                )
                if registry and registry[1] == account and registry[2] == region:
                    repository = f"{prefix}:ecr:{region}:{account}:repository/{registry[3]}"
                    node(repository, "repository", registry[3])
                    edges.add((key, repository, "uses_image_repository"))
            source = container.get("ModelDataSource", {})
            s3 = source.get("S3DataSource", {}) if isinstance(source, dict) else {}
            uri = container.get("ModelDataUrl") or (s3.get("S3Uri") if isinstance(s3, dict) else None)
            if isinstance(uri, str) and uri.startswith("s3://"):
                bucket = uri[5:].split("/", 1)[0]
                if BUCKET.fullmatch(bucket):
                    bucket_id = f"{prefix}:s3:::{bucket}"
                    node(bucket_id, "data", bucket)
                    edges.add((key, bucket_id, "stores_artifacts"))

    for listed in page(call, "sagemaker", "list-endpoints", "Endpoints"):
        name = scalar(listed.get("EndpointName"), NAME, "endpoint name")
        key = f"{prefix}:sagemaker:{region}:{account}:endpoint/{name}"
        record = call("sagemaker", "describe-endpoint", "--endpoint-name", name)
        if record.get("EndpointArn") != key:
            raise CollectionError("AWS returned an unexpected SageMaker endpoint.")
        config = scalar(record.get("EndpointConfigName"), NAME, "endpoint configuration name")
        if config not in configurations:
            configuration = call("sagemaker", "describe-endpoint-config", "--endpoint-config-name", config)
            if configuration.get("EndpointConfigArn") != f"{prefix}:sagemaker:{region}:{account}:endpoint-config/{config}":
                raise CollectionError("AWS returned an unexpected SageMaker endpoint configuration.")
            configurations[config] = configuration
        node(key, "endpoint", name)
        for variant in objects(configurations[config], "ProductionVariants"):
            deployed = variant.get("ModelName")
            if isinstance(deployed, str) and deployed in model_keys:
                edges.add((key, model_keys[deployed], "serves"))

    for listed in page(call, "bedrock-agent", "list-agents", "agentSummaries"):
        agent_id = scalar(listed.get("agentId"), AGENT_ID, "agent ID")
        key = f"{prefix}:bedrock:{region}:{account}:agent/{agent_id}"
        agent = call("bedrock-agent", "get-agent", "--agent-id", agent_id).get("agent")
        if not isinstance(agent, dict) or agent.get("agentArn") != key:
            raise CollectionError("AWS returned an unexpected Bedrock agent.")
        label = agent.get("agentName")
        node(key, "agent", label if isinstance(label, str) and label.isprintable() and len(label) <= 100 else agent_id)
        role(key, agent.get("agentResourceRoleArn"))
        model = agent.get("foundationModel")
        if isinstance(model, str) and 1 <= len(model) <= 250 and re.fullmatch(r"[A-Za-z0-9_./:@-]+", model):
            key_model = "bedrock-model:" + model
            node(key_model, "model", model)
            edges.add((key, key_model, "uses_model"))

    if analyzer:
        match = ARN.fullmatch(analyzer)
        if (not match or match[1] != identity[1] or match.groups()[1:4] != ("access-analyzer", region, account)
                or not match[5].startswith("analyzer/")):
            raise CollectionError("Use an Access Analyzer ARN in the selected AWS region and account.")
        findings = page(call, "accessanalyzer", "list-findings-v2", "findings",
                        ("--analyzer-arn", analyzer), limit=2000)
        states = {}
        for item in findings:
            resource = item.get("resource")
            if (not isinstance(resource, str) or resource not in nodes or nodes[resource]["kind"] != "identity"
                    or item.get("resourceOwnerAccount") != account or item.get("findingType") != "ExternalAccess"
                    or item.get("error")):
                continue
            if item.get("status") in ("ACTIVE", "RESOLVED"):
                states.setdefault(resource, set()).add(item["status"])
        for resource, status in states.items():
            nodes[resource]["exposure"] = "analyzer_external_access" if "ACTIVE" in status else "analyzer_resolved"
    return nodes, sorted(edges)
