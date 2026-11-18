"""Read-only inventory of Agentforce metadata on Salesforce API v68+."""
import re
from urllib.request import Request, build_opener
from xml.etree import ElementTree as XML

from gcs import CollectionError, NoRedirect

SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
META = "http://soap.sforce.com/2006/04/metadata"
TYPES = {"AiAgentDefinition": "agent", "AiAgentDefinitionVersion": "automation"}
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,254}")
VERSION = re.compile(r"([A-Za-z][A-Za-z0-9_]{0,254})#[1-9][0-9]{0,8}")


def list_metadata(origin, api_version, token, kind, *, opener=None):
    envelope = XML.Element(f"{{{SOAP}}}Envelope")
    headers = XML.SubElement(envelope, f"{{{SOAP}}}Header")
    session = XML.SubElement(headers, f"{{{META}}}SessionHeader")
    XML.SubElement(session, f"{{{META}}}sessionId").text = token
    body = XML.SubElement(envelope, f"{{{SOAP}}}Body")
    listing = XML.SubElement(body, f"{{{META}}}listMetadata")
    query = XML.SubElement(listing, f"{{{META}}}queries")
    XML.SubElement(query, f"{{{META}}}type").text = kind
    XML.SubElement(listing, f"{{{META}}}asOfVersion").text = api_version

    request = Request(origin + "/services/Soap/m/" + api_version, data=XML.tostring(envelope),
                      headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'})
    try:
        with (opener or build_opener(NoRedirect())).open(request, timeout=20) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError()
        text = raw.decode("utf-8")
        if "<!" in text or "\0" in text:
            raise ValueError()
        root = XML.fromstring(text)
    except (OSError, ValueError, XML.ParseError) as exc:
        if hasattr(exc, "close"):
            exc.close()
        raise CollectionError("Salesforce Agentforce metadata request failed.") from None
    result = root.find(f"{{{SOAP}}}Body/{{{META}}}listMetadataResponse")
    if result is None:
        raise CollectionError("Salesforce returned an invalid metadata response.")
    names = []
    for record in result:
        if record.tag != f"{{{META}}}result":
            raise CollectionError("Salesforce returned unexpected Agentforce metadata.")
        if record.get("{http://www.w3.org/2001/XMLSchema-instance}nil") in ("true", "1"):
            continue
        if record.findtext(f"{{{META}}}type") != kind:
            raise CollectionError("Salesforce returned a different metadata type.")
        names.append(record.findtext(f"{{{META}}}fullName"))
    return names


def collect(origin, api_version, token, org, nodes, edges, *, listing=list_metadata):
    for kind, graph_kind in TYPES.items():
        names = listing(origin, api_version, token, kind)
        if len(nodes) + len(names) > 500:
            raise CollectionError("Salesforce inventory exceeded the 500 asset limit.")
        for name in names:
            match = (NAME if graph_kind == "agent" else VERSION).fullmatch(name or "")
            if match is None:
                raise CollectionError("Salesforce returned an invalid Agentforce component name.")
            key = "metadata:" + kind + ":" + name
            if key in nodes:
                raise CollectionError("Salesforce returned duplicate Agentforce metadata.")
            nodes[key] = {"kind": graph_kind, "name": name}
            if graph_kind == "agent":
                edges.append((org, key, "contains"))
            else:
                parent = "metadata:AiAgentDefinition:" + match[1]
                if parent in nodes:
                    edges.append((parent, key, "contains"))
