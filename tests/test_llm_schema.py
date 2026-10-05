from pydantic import BaseModel

from tipipeline.llm import strict_json_schema


class NamedResult(BaseModel):
    title: str
    default: str


class Results(BaseModel):
    title: str
    records: list[NamedResult]


def test_structured_output_preserves_fields_named_like_schema_annotations():
    schema = strict_json_schema(Results)
    nested = schema["$defs"]["NamedResult"]
    assert schema["properties"]["title"]["type"] == "string"
    assert nested["properties"]["title"]["type"] == "string"
    assert nested["properties"]["default"]["type"] == "string"
    for node in (schema, nested):
        assert set(node["required"]) == set(node["properties"])
        assert node["additionalProperties"] is False
