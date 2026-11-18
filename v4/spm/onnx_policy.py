"""Detect external tensor references and custom code dependencies in signed ONNX files."""
from controls import Problem

LIMIT = 64 * 1024 * 1024
STANDARD_DOMAINS = {"", "ai.onnx", "ai.onnx.ml"}


def inspect(file, size):
    if not 1 <= size <= LIMIT:
        raise Problem(400, "ONNX policy supports artifacts up to 64 MiB.")
    try:
        import onnx
        from google.protobuf.message import DecodeError
    except ImportError:
        raise Problem(400, "Install the ONNX policy dependencies before using this format.") from None

    file.seek(0)
    model = onnx.ModelProto()
    try:
        model.ParseFromString(file.read(size))
    except DecodeError:
        raise Problem(400, "Invalid ONNX protobuf artifact.") from None
    if model.ir_version < 1 or not model.HasField("graph") or not model.opset_import:
        raise Problem(400, "ONNX artifact is missing required model metadata.")
    if model.functions or model.training_info:
        raise Problem(400, "ONNX policy rejects model-local functions and training graphs.")
    if any(opset.domain not in STANDARD_DOMAINS or opset.version < 1 for opset in model.opset_import):
        raise Problem(400, "ONNX policy rejects custom operator sets or invalid versions.")

    pending = [(model.graph, 0)]
    visited = nodes = tensors = 0
    while pending:
        message, depth = pending.pop()
        visited += 1
        if depth > 32 or visited + len(pending) > 200_000:
            raise Problem(400, "ONNX graph exceeds inspection limits.")
        if isinstance(message, onnx.TensorProto):
            tensors += 1
            if message.external_data or message.data_location != onnx.TensorProto.DEFAULT:
                raise Problem(400, "ONNX policy rejects external tensor data.")
        if isinstance(message, onnx.NodeProto):
            nodes += 1
            if message.domain not in STANDARD_DOMAINS or not message.op_type:
                raise Problem(400, "ONNX policy rejects custom or invalid operators.")
        for field, value in message.ListFields():
            if field.message_type is not None:
                if field.is_repeated:
                    if visited + len(pending) + len(value) > 200_000:
                        raise Problem(400, "ONNX graph exceeds inspection limits.")
                    pending.extend((child, depth + 1) for child in value)
                else:
                    pending.append((value, depth + 1))
    return {"format": "onnx-inline", "nodes_checked": nodes, "tensors_checked": tensors,
            "ir_version": model.ir_version}
