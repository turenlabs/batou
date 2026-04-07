import json
import ast
from typing import Any

import yaml

# SAFE: yaml.safe_load (not yaml.load with FullLoader/Loader)
def parse_config(raw: str) -> dict:
    return yaml.safe_load(raw)


# SAFE: yaml.safe_load_all for multi-document YAML
def parse_multi_config(raw: str) -> list:
    return list(yaml.safe_load_all(raw))


# SAFE: json.loads (always safe for deserialization)
def parse_json_body(body: str) -> Any:
    return json.loads(body)


# SAFE: ast.literal_eval (only evaluates literals, not arbitrary code)
def parse_python_literal(value: str) -> Any:
    return ast.literal_eval(value)


# SAFE: yaml.dump with default_flow_style (serialization, not deserialization)
def serialize_config(data: dict) -> str:
    return yaml.dump(data, default_flow_style=False)
