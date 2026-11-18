"""Bounded, read-only text classification for explicitly selected cloud objects."""
import codecs
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, build_opener

from aws_inventory import cli as aws_cli
from gcs import CollectionError, NoRedirect, access_token, fetch_google
from gcs_access import BUCKET_API, bucket_revision
from runtime_policy import PATTERNS

LIMIT = 65536
AWS_BUCKET = re.compile(r"arn:(aws(?:-[a-z0-9-]+)?):s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])")
OBJECT = re.compile(r"[A-Za-z0-9_./ -]{1,512}")


def object_key(key):
    if not OBJECT.fullmatch(key) or any(part in ("", ".", "..") for part in key.split("/")):
        raise CollectionError("Supply one exact supported object key without wildcards.")


def s3(bucket, owner, region, key):
    with TemporaryDirectory() as temp:
        output = Path(temp) / "sample"
        try:
            subprocess.run(["aws", "--region", region, "--no-cli-pager", "s3api", "get-object",
                            "--bucket", bucket, "--expected-bucket-owner", owner, "--key=" + key,
                            "--range", f"bytes=0-{LIMIT - 1}", os.fspath(output)],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=25, check=True)
            with output.open("rb") as sample:
                raw = sample.read(LIMIT + 1)
        except (OSError, subprocess.SubprocessError):
            raise CollectionError("S3 sample fetch failed. Verify bucket ownership and object read access.") from None
    return raw


def gcs(bucket, project_number, key, *, credential=access_token, fetch=fetch_google, opener=None):
    token = credential()
    endpoint = f"{BUCKET_API}/{bucket}"
    arguments = (fetch, endpoint, bucket, project_number, token, None)
    before = bucket_revision(*arguments)
    request = Request(endpoint + "/o/" + quote(key, safe="") + "?alt=media", headers={
        "Authorization": "Bearer " + token, "Range": f"bytes=0-{LIMIT - 1}", "Accept-Encoding": "identity",
    })
    try:
        with (opener or build_opener(NoRedirect())).open(request, timeout=15) as response:
            raw = response.read(LIMIT + 1)
    except HTTPError as error:
        error.close()
        raise CollectionError(f"Cloud Storage sample fetch returned HTTP {error.code}.") from None
    except OSError:
        raise CollectionError("Cloud Storage sample fetch failed.") from None
    if bucket_revision(*arguments) != before:
        raise CollectionError("Cloud Storage bucket metadata changed during sampling.")
    return raw


def listed_objects(entries, key_field, size_field, prefix, count, truncated):
    if not isinstance(entries, list) or len(entries) > count:
        raise CollectionError("Provider returned invalid object listing metadata.")
    keys, seen = [], set()
    for entry in entries:
        key = entry.get(key_field) if isinstance(entry, dict) else None
        size = entry.get(size_field) if isinstance(entry, dict) else None
        if (not isinstance(key, str) or not key.startswith(prefix) or key in seen
                or not ((type(size) is int and size >= 0) or (isinstance(size, str)
                        and re.fullmatch(r"[0-9]{1,20}", size)))):
            raise CollectionError("Provider returned invalid or out-of-prefix object metadata.")
        seen.add(key)
        if int(size) == 0 or not key.lower().endswith((".txt", ".csv", ".json", ".jsonl", ".log", ".md", ".tsv")):
            continue
        try:
            object_key(key)
        except CollectionError:
            continue
        keys.append(key)
    return keys, len(entries) - len(keys), truncated


def list_s3(bucket, owner, region, prefix, count, *, invoke=aws_cli):
    reply = invoke(region, "s3api", "list-objects-v2", "--no-paginate", "--bucket", bucket,
                   "--expected-bucket-owner", owner, "--prefix=" + prefix, "--max-keys", str(count))
    if type(reply.get("IsTruncated")) is not bool:
        raise CollectionError("S3 returned an invalid listing boundary.")
    return listed_objects(reply.get("Contents", []), "Key", "Size", prefix, count, reply["IsTruncated"])


def list_gcs(bucket, project_number, prefix, count, *, credential=access_token, fetch=fetch_google):
    token = credential()
    endpoint = f"{BUCKET_API}/{bucket}"
    arguments = (fetch, endpoint, bucket, project_number, token, None)
    before = bucket_revision(*arguments)
    reply = fetch(endpoint + "/o", {"prefix": prefix, "maxResults": count,
                                   "fields": "items(name,size),nextPageToken"},
                  token, None, "Cloud Storage object discovery")
    if not isinstance(reply, dict) or ("nextPageToken" in reply and not isinstance(reply["nextPageToken"], str)):
        raise CollectionError("Cloud Storage returned an invalid listing boundary.")
    if bucket_revision(*arguments) != before:
        raise CollectionError("Cloud Storage bucket metadata changed during listing.")
    return listed_objects(reply.get("items", []), "name", "size", prefix, count, bool(reply.get("nextPageToken")))


PAYMENT = re.compile(r"(?i)\b(?:card(?: number)?|pan)\s*[:=]\s*((?:[0-9][ -]?){12,18}[0-9])(?![0-9 -]*[0-9])")
SSN = re.compile(r"(?i)\b(?:ssn|social security(?: number)?)\s*[:=]\s*([0-9]{3})-([0-9]{2})-([0-9]{4})(?![0-9])")


def luhn(value):
    digits = [int(char) for char in value if char.isascii() and char.isdigit()]
    return (len(set(digits)) > 1 and sum(
        (number * 2 - 9 if number > 4 else number * 2) if index % 2 else number
        for index, number in enumerate(reversed(digits))
    ) % 10 == 0)


def classify(raw):
    if not 1 <= len(raw) <= LIMIT:
        raise CollectionError("Object content is empty or exceeds the sample limit.")
    try:
        text = codecs.getincrementaldecoder("utf-8")().decode(raw, final=len(raw) < LIMIT)
    except UnicodeError:
        raise CollectionError("The sampled object must contain UTF-8 text.") from None
    if "\0" in text:
        raise CollectionError("The sampled object contains binary data.")
    signals = {}
    for label, pattern in PATTERNS:
        text, count = pattern.subn("", text)
        if count:
            signals[label] = count
    payment = sum(luhn(match[1]) for match in PAYMENT.finditer(text))
    ssn = sum(match[1] not in ("000", "666") and int(match[1]) < 900 and match[2] != "00"
              and match[3] != "0000" for match in SSN.finditer(text))
    if payment:
        signals["payment_card_candidate"] = payment
    if ssn:
        signals["us_ssn_candidate"] = ssn
    level = "high" if set(signals) - {"email_address"} else "moderate" if signals else "unknown"
    return {"sensitivity": level, "signals": signals, "sample_bytes": len(raw)}
