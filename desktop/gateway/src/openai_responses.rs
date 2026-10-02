use serde_json::{json, Map, Value};
use std::collections::HashSet;

const DEFAULT_RESPONSES_CAP: u64 = 65_536;
const DASHSCOPE_RESPONSES_TOOLS_CAP: u64 = 8_192;
const MAX_TOOL_ARGUMENT_BYTES: usize = 1_048_576;
const MAX_SCHEMA_DEPTH: usize = 64;
const MAX_SCHEMA_NODES: usize = 20_000;
const TOOL_ARGUMENT_PROTOCOL_ERROR: &str =
    "upstream tool arguments failed the declared input schema";
const RULE_PROVIDER_DASHSCOPE_RESPONSES_TOOLS_CAP: &str = "provider.dashscope.responses-tools-cap";
const RULE_TOOL_DASHSCOPE_RESPONSES_WEB_SEARCH_DROP: &str =
    "tool.dashscope.responses.web_search-drop";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsesMetadata {
    pub rule_ids: Vec<String>,
}

pub fn is_dashscope_responses_endpoint(provider: &str, upstream_url: &str) -> bool {
    if provider != "openai-responses" {
        return false;
    }
    let Some((_raw_scheme, remainder)) = upstream_url.split_once("://") else {
        return false;
    };
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || !authority.is_ascii() || authority.contains('@') {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(upstream_url) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    parsed
        .host_str()
        .map(|hostname| hostname.strip_suffix('.').unwrap_or(hostname))
        .is_some_and(|hostname| hostname.eq_ignore_ascii_case("dashscope.aliyuncs.com"))
}

fn append_rule_id(rule_ids: &mut Vec<String>, rule_id: &str) {
    if !rule_ids.iter().any(|existing| existing == rule_id) {
        rule_ids.push(rule_id.to_string());
    }
}

fn json_dumps_python_style(value: &Value) -> String {
    let compact = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    let mut out = String::with_capacity(compact.len() + 8);
    let mut in_string = false;
    let mut escaped = false;
    for ch in compact.chars() {
        out.push(ch);
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
        } else if ch == ':' || ch == ',' {
            out.push(' ');
        }
    }
    out
}

fn as_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        Some(other) => json_dumps_python_style(other),
        None => String::new(),
    }
}

fn system_prompt(system: Option<&Value>) -> Option<String> {
    let prompt = match system {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    };
    if prompt.is_empty() {
        None
    } else {
        Some(prompt)
    }
}

fn normalize_tool_parameters(schema: Option<&Value>) -> Value {
    let Some(Value::Object(obj)) = schema else {
        return json!({"type": "object", "properties": {}});
    };
    let mut out = obj.clone();
    if out.contains_key("properties") && !out.contains_key("type") {
        out.insert("type".to_string(), Value::String("object".to_string()));
    }
    if out.get("type").and_then(Value::as_str) != Some("object") {
        return json!({"type": "object", "properties": {}});
    }
    if !out.get("properties").map(Value::is_object).unwrap_or(false) {
        out.insert("properties".to_string(), json!({}));
    }
    Value::Object(out)
}

fn map_tools(tools: Option<&Value>, is_dashscope: bool, rule_ids: &mut Vec<String>) -> Vec<Value> {
    let mut out = Vec::new();
    for tool in tools.and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        if is_dashscope && name == "web_search" {
            append_rule_id(rule_ids, RULE_TOOL_DASHSCOPE_RESPONSES_WEB_SEARCH_DROP);
            continue;
        }
        out.push(json!({
            "type": "function",
            "name": name,
            "description": tool.get("description").and_then(Value::as_str).unwrap_or(""),
            "parameters": normalize_tool_parameters(tool.get("input_schema")),
        }));
    }
    out
}

fn map_tool_choice(tool_choice: Option<&Value>, has_tools: bool) -> Option<Value> {
    let kind = match tool_choice {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Object(obj)) => obj.get("type").and_then(Value::as_str),
        _ => None,
    };
    match kind {
        Some("auto") => Some(Value::String("auto".to_string())),
        Some("none") => Some(Value::String("none".to_string())),
        _ if has_tools => Some(Value::String("auto".to_string())),
        _ => None,
    }
}

fn max_output_tokens(
    value: Option<u64>,
    has_tools: bool,
    is_dashscope: bool,
    rule_ids: &mut Vec<String>,
) -> Option<u64> {
    let value = value?.min(DEFAULT_RESPONSES_CAP);
    if has_tools && is_dashscope {
        append_rule_id(rule_ids, RULE_PROVIDER_DASHSCOPE_RESPONSES_TOOLS_CAP);
        Some(value.min(DASHSCOPE_RESPONSES_TOOLS_CAP))
    } else {
        Some(value)
    }
}

pub fn anthropic_to_openai(
    req: &Value,
    target_model: &str,
    is_dashscope: bool,
) -> Result<(Value, ResponsesMetadata), String> {
    let obj = req
        .as_object()
        .ok_or("request body must be a JSON object with a 'messages' array")?;
    if !obj.get("messages").map(Value::is_array).unwrap_or(false) {
        return Err("request body must be a JSON object with a 'messages' array".to_string());
    }

    let mut rule_ids = Vec::new();
    let mut items = Vec::new();
    for message in obj.get("messages").and_then(Value::as_array).unwrap() {
        let role = message.get("role").cloned().unwrap_or(Value::Null);
        let content = message.get("content").unwrap_or(&Value::Null);
        if let Some(text) = content.as_str() {
            items.push(json!({"role": role, "content": text}));
            continue;
        }

        let mut text_parts = Vec::new();
        for block in content.as_array().into_iter().flatten() {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    text_parts.push(block.get("text").and_then(Value::as_str).unwrap_or(""));
                }
                Some("tool_use") => {
                    if !text_parts.is_empty() {
                        items.push(json!({"role": role.clone(), "content": text_parts.join("")}));
                        text_parts.clear();
                    }
                    let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
                    items.push(json!({
                        "type": "function_call",
                        "call_id": block.get("id").cloned().unwrap_or(Value::Null),
                        "name": block.get("name").cloned().unwrap_or(Value::Null),
                        "arguments": json_dumps_python_style(&input),
                    }));
                }
                Some("tool_result") => {
                    if !text_parts.is_empty() {
                        items.push(json!({"role": role.clone(), "content": text_parts.join("")}));
                        text_parts.clear();
                    }
                    items.push(json!({
                        "type": "function_call_output",
                        "call_id": block.get("tool_use_id").cloned().unwrap_or(Value::Null),
                        "output": as_text(block.get("content")),
                    }));
                }
                _ => {}
            }
        }
        if !text_parts.is_empty() {
            items.push(json!({"role": role, "content": text_parts.join("")}));
        }
    }

    let tools = map_tools(obj.get("tools"), is_dashscope, &mut rule_ids);
    let has_tools = !tools.is_empty();
    let mut out = Map::new();
    out.insert("model".to_string(), Value::String(target_model.to_string()));
    out.insert("input".to_string(), Value::Array(items));
    out.insert("stream".to_string(), Value::Bool(false));
    if let Some(prompt) = system_prompt(obj.get("system")) {
        out.insert("instructions".to_string(), Value::String(prompt));
    }
    if let Some(value) = max_output_tokens(
        obj.get("max_tokens").and_then(Value::as_u64),
        has_tools,
        is_dashscope,
        &mut rule_ids,
    ) {
        out.insert(
            "max_output_tokens".to_string(),
            Value::Number(serde_json::Number::from(value)),
        );
    }
    if let Some(temperature) = obj.get("temperature") {
        if !temperature.is_null() {
            out.insert("temperature".to_string(), temperature.clone());
        }
    }
    if let Some(top_p) = obj.get("top_p") {
        if !top_p.is_null() {
            out.insert("top_p".to_string(), top_p.clone());
        }
    }
    if has_tools {
        out.insert("tools".to_string(), Value::Array(tools));
    }
    if let Some(mapped) = map_tool_choice(obj.get("tool_choice"), has_tools) {
        out.insert("tool_choice".to_string(), mapped);
    }
    Ok((Value::Object(out), ResponsesMetadata { rule_ids }))
}

fn output_text(item: &Value) -> String {
    item.get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|content| {
            let kind = content.get("type").and_then(Value::as_str)?;
            if kind == "output_text" || kind == "text" {
                content.get("text").and_then(Value::as_str)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

struct SchemaBudget {
    nodes: usize,
}

impl SchemaBudget {
    fn enter(&mut self, depth: usize) -> bool {
        if depth > MAX_SCHEMA_DEPTH || self.nodes >= MAX_SCHEMA_NODES {
            return false;
        }
        self.nodes += 1;
        true
    }
}

fn value_matches_type(instance: &Value, kind: &str) -> bool {
    match kind {
        "null" => instance.is_null(),
        "boolean" => instance.is_boolean(),
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "number" => instance.is_number(),
        "integer" => instance
            .as_number()
            .is_some_and(|number| number.is_i64() || number.is_u64()),
        "string" => instance.is_string(),
        _ => false,
    }
}

fn instance_type_matches(instance: &Value, schema_type: &Value) -> bool {
    match schema_type {
        Value::String(kind) => value_matches_type(instance, kind),
        Value::Array(kinds) if !kinds.is_empty() => {
            kinds.iter().all(Value::is_string)
                && kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|kind| value_matches_type(instance, kind))
        }
        _ => false,
    }
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    if reference == "#" {
        return Some(root);
    }
    reference
        .strip_prefix('#')
        .filter(|pointer| pointer.starts_with('/'))
        .and_then(|pointer| root.pointer(pointer))
}

fn number_keyword(schema: &Map<String, Value>, key: &str) -> Option<Option<f64>> {
    schema.get(key).map(|value| value.as_f64())
}

fn nonnegative_usize_keyword(schema: &Map<String, Value>, key: &str) -> Option<Option<usize>> {
    schema
        .get(key)
        .map(|value| value.as_u64().and_then(|value| usize::try_from(value).ok()))
}

fn validate_schema_instance(
    instance: &Value,
    schema: &Value,
    root: &Value,
    depth: usize,
    budget: &mut SchemaBudget,
    ref_stack: &mut HashSet<String>,
) -> bool {
    if !budget.enter(depth) {
        return false;
    }
    match schema {
        Value::Bool(allowed) => return *allowed,
        Value::Object(_) => {}
        _ => return false,
    }
    let object = schema.as_object().expect("schema object checked");
    const SUPPORTED_KEYWORDS: &[&str] = &[
        "$comment",
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "default",
        "dependentRequired",
        "deprecated",
        "description",
        "else",
        "enum",
        "examples",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "if",
        "items",
        "maximum",
        "maxItems",
        "maxLength",
        "maxProperties",
        "minimum",
        "minItems",
        "minLength",
        "minProperties",
        "multipleOf",
        "not",
        "oneOf",
        "pattern",
        "properties",
        "readOnly",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
        "writeOnly",
    ];
    if object
        .keys()
        .any(|keyword| !SUPPORTED_KEYWORDS.contains(&keyword.as_str()))
    {
        return false;
    }

    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let Some(target) = resolve_local_ref(root, reference) else {
            return false;
        };
        if !ref_stack.insert(reference.to_string()) {
            return false;
        }
        let valid = validate_schema_instance(instance, target, root, depth + 1, budget, ref_stack);
        ref_stack.remove(reference);
        if !valid {
            return false;
        }
    } else if object.contains_key("$ref") {
        return false;
    }

    if object
        .get("type")
        .is_some_and(|kind| !instance_type_matches(instance, kind))
    {
        return false;
    }
    if object
        .get("const")
        .is_some_and(|expected| instance != expected)
    {
        return false;
    }
    if let Some(values) = object.get("enum") {
        let Some(values) = values.as_array() else {
            return false;
        };
        if values.is_empty() || !values.iter().any(|expected| expected == instance) {
            return false;
        }
    }

    for keyword in ["allOf", "anyOf", "oneOf"] {
        let Some(raw_branches) = object.get(keyword) else {
            continue;
        };
        let Some(branches) = raw_branches
            .as_array()
            .filter(|branches| !branches.is_empty())
        else {
            return false;
        };
        let matches = branches
            .iter()
            .filter(|branch| {
                let mut branch_budget = SchemaBudget {
                    nodes: budget.nodes,
                };
                let mut branch_refs = ref_stack.clone();
                validate_schema_instance(
                    instance,
                    branch,
                    root,
                    depth + 1,
                    &mut branch_budget,
                    &mut branch_refs,
                )
            })
            .count();
        let valid = match keyword {
            "allOf" => matches == branches.len(),
            "anyOf" => matches >= 1,
            "oneOf" => matches == 1,
            _ => unreachable!(),
        };
        if !valid {
            return false;
        }
    }
    if let Some(negated) = object.get("not") {
        let mut branch_budget = SchemaBudget {
            nodes: budget.nodes,
        };
        let mut branch_refs = ref_stack.clone();
        if validate_schema_instance(
            instance,
            negated,
            root,
            depth + 1,
            &mut branch_budget,
            &mut branch_refs,
        ) {
            return false;
        }
    }

    if let Some(condition) = object.get("if") {
        let mut condition_budget = SchemaBudget {
            nodes: budget.nodes,
        };
        let mut condition_refs = ref_stack.clone();
        let condition_matches = validate_schema_instance(
            instance,
            condition,
            root,
            depth + 1,
            &mut condition_budget,
            &mut condition_refs,
        );
        if let Some(branch) = object.get(if condition_matches { "then" } else { "else" }) {
            if !validate_schema_instance(instance, branch, root, depth + 1, budget, ref_stack) {
                return false;
            }
        }
    } else if object.contains_key("then") || object.contains_key("else") {
        return false;
    }

    if let Some(map) = instance.as_object() {
        if let Some(Some(min)) = nonnegative_usize_keyword(object, "minProperties") {
            if map.len() < min {
                return false;
            }
        } else if object.get("minProperties").is_some() {
            return false;
        }
        if let Some(Some(max)) = nonnegative_usize_keyword(object, "maxProperties") {
            if map.len() > max {
                return false;
            }
        } else if object.get("maxProperties").is_some() {
            return false;
        }
        if let Some(required) = object.get("required") {
            let Some(required) = required.as_array() else {
                return false;
            };
            let mut seen = HashSet::new();
            for name in required {
                let Some(name) = name.as_str() else {
                    return false;
                };
                if !seen.insert(name) || !map.contains_key(name) {
                    return false;
                }
            }
        }
        let properties = match object.get("properties") {
            Some(Value::Object(properties)) => Some(properties),
            Some(_) => return false,
            None => None,
        };
        for (name, value) in map {
            if let Some(property_schema) = properties.and_then(|properties| properties.get(name)) {
                if !validate_schema_instance(
                    value,
                    property_schema,
                    root,
                    depth + 1,
                    budget,
                    ref_stack,
                ) {
                    return false;
                }
                continue;
            }
            match object.get("additionalProperties") {
                Some(Value::Bool(false)) => return false,
                Some(Value::Bool(true)) | None => {}
                Some(additional_schema @ Value::Object(_)) => {
                    if !validate_schema_instance(
                        value,
                        additional_schema,
                        root,
                        depth + 1,
                        budget,
                        ref_stack,
                    ) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        if let Some(dependencies) = object.get("dependentRequired") {
            let Some(dependencies) = dependencies.as_object() else {
                return false;
            };
            for (name, required) in dependencies {
                if !map.contains_key(name) {
                    continue;
                }
                let Some(required) = required.as_array() else {
                    return false;
                };
                if required
                    .iter()
                    .any(|required| required.as_str().is_none_or(|name| !map.contains_key(name)))
                {
                    return false;
                }
            }
        }
    }

    if let Some(items) = instance.as_array() {
        if let Some(Some(min)) = nonnegative_usize_keyword(object, "minItems") {
            if items.len() < min {
                return false;
            }
        } else if object.get("minItems").is_some() {
            return false;
        }
        if let Some(Some(max)) = nonnegative_usize_keyword(object, "maxItems") {
            if items.len() > max {
                return false;
            }
        } else if object.get("maxItems").is_some() {
            return false;
        }
        if object.get("uniqueItems").and_then(Value::as_bool) == Some(true)
            && items
                .iter()
                .enumerate()
                .any(|(index, item)| items[index + 1..].contains(item))
        {
            return false;
        }
        if object
            .get("uniqueItems")
            .is_some_and(|value| !value.is_boolean())
        {
            return false;
        }
        if let Some(item_schema) = object.get("items") {
            if item_schema.is_array()
                || items.iter().any(|item| {
                    !validate_schema_instance(item, item_schema, root, depth + 1, budget, ref_stack)
                })
            {
                return false;
            }
        }
    }

    if let Some(text) = instance.as_str() {
        let char_count = text.chars().count();
        if let Some(Some(min)) = nonnegative_usize_keyword(object, "minLength") {
            if char_count < min {
                return false;
            }
        } else if object.get("minLength").is_some() {
            return false;
        }
        if let Some(Some(max)) = nonnegative_usize_keyword(object, "maxLength") {
            if char_count > max {
                return false;
            }
        } else if object.get("maxLength").is_some() {
            return false;
        }
        if let Some(pattern) = object.get("pattern") {
            let Some(pattern) = pattern.as_str() else {
                return false;
            };
            let Ok(pattern) = regex::Regex::new(pattern) else {
                return false;
            };
            if !pattern.is_match(text) {
                return false;
            }
        }
    }

    if let Some(number) = instance.as_f64() {
        if let Some(bound) = number_keyword(object, "minimum") {
            let Some(bound) = bound else {
                return false;
            };
            if number < bound {
                return false;
            }
        }
        if let Some(bound) = number_keyword(object, "maximum") {
            let Some(bound) = bound else {
                return false;
            };
            if number > bound {
                return false;
            }
        }
        if let Some(bound) = number_keyword(object, "exclusiveMinimum") {
            let Some(bound) = bound else {
                return false;
            };
            if number <= bound {
                return false;
            }
        }
        if let Some(bound) = number_keyword(object, "exclusiveMaximum") {
            let Some(bound) = bound else {
                return false;
            };
            if number >= bound {
                return false;
            }
        }
        if let Some(divisor) = number_keyword(object, "multipleOf") {
            let Some(divisor) = divisor.filter(|divisor| *divisor > 0.0) else {
                return false;
            };
            let quotient = number / divisor;
            if (quotient - quotient.round()).abs() > 1e-9 {
                return false;
            }
        }
    }
    true
}

fn tool_arguments_match_schema(arguments: &Value, schema: &Value) -> bool {
    let mut budget = SchemaBudget { nodes: 0 };
    validate_schema_instance(
        arguments,
        schema,
        schema,
        0,
        &mut budget,
        &mut HashSet::new(),
    )
}

pub fn openai_to_anthropic(resp: &Value, model_id: &str) -> Value {
    let mut blocks = Vec::new();
    for item in resp
        .get("output")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => {
                let text = output_text(item);
                if !text.is_empty() {
                    blocks.push(json!({"type": "text", "text": text}));
                }
            }
            Some("function_call") => {
                let raw_args = item
                    .get("arguments")
                    .and_then(Value::as_str)
                    .unwrap_or("{}");
                let args = serde_json::from_str::<Value>(raw_args).unwrap_or_else(|_| json!({}));
                blocks.push(json!({
                    "type": "tool_use",
                    "id": item.get("call_id").or_else(|| item.get("id")).cloned().unwrap_or(Value::Null),
                    "name": item.get("name").cloned().unwrap_or(Value::Null),
                    "input": args,
                }));
            }
            _ => {}
        }
    }
    if blocks.is_empty() {
        if let Some(text) = resp.get("output_text").and_then(Value::as_str) {
            if !text.is_empty() {
                blocks.push(json!({"type": "text", "text": text}));
            }
        }
    }
    let stop_reason = if resp.get("status").and_then(Value::as_str) == Some("incomplete") {
        "max_tokens"
    } else if blocks
        .iter()
        .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
    {
        "tool_use"
    } else {
        "end_turn"
    };
    let usage = resp.get("usage").unwrap_or(&Value::Null);
    json!({
        "id": resp.get("id").and_then(Value::as_str).unwrap_or("msg_proxy"),
        "type": "message",
        "role": "assistant",
        "model": model_id,
        "content": if blocks.is_empty() { vec![json!({"type": "text", "text": ""})] } else { blocks },
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": usage.get("input_tokens").and_then(Value::as_u64).unwrap_or(0),
            "output_tokens": usage.get("output_tokens").and_then(Value::as_u64).unwrap_or(0),
        },
    })
}

pub fn openai_to_anthropic_validated(
    resp: &Value,
    model_id: &str,
    known_tools: &Map<String, Value>,
) -> Result<Value, String> {
    for item in resp
        .get("output")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
    {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            return Err(TOOL_ARGUMENT_PROTOCOL_ERROR.to_string());
        };
        let Some(schema) = known_tools.get(name) else {
            return Err(TOOL_ARGUMENT_PROTOCOL_ERROR.to_string());
        };
        let Some(raw_arguments) = item.get("arguments").and_then(Value::as_str) else {
            return Err(TOOL_ARGUMENT_PROTOCOL_ERROR.to_string());
        };
        if raw_arguments.len() > MAX_TOOL_ARGUMENT_BYTES {
            return Err(TOOL_ARGUMENT_PROTOCOL_ERROR.to_string());
        }
        let Ok(arguments) = serde_json::from_str::<Value>(raw_arguments) else {
            return Err(TOOL_ARGUMENT_PROTOCOL_ERROR.to_string());
        };
        if !arguments.is_object() || !tool_arguments_match_schema(&arguments, schema) {
            return Err(TOOL_ARGUMENT_PROTOCOL_ERROR.to_string());
        }
    }
    Ok(openai_to_anthropic(resp, model_id))
}

#[cfg(test)]
mod tests {
    use super::{anthropic_to_openai, is_dashscope_responses_endpoint, openai_to_anthropic};
    use serde_json::{json, Value};

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../../test/golden/openai_responses.json")).unwrap()
    }

    #[test]
    fn responses_transform_matches_python_fixture() {
        let fixture = fixture();
        let (mapped, metadata) =
            anthropic_to_openai(&fixture["request"], "gpt-5.2", false).unwrap();
        assert_eq!(mapped, fixture["mapped"]);
        assert_eq!(metadata.rule_ids, Vec::<String>::new());
    }

    #[test]
    fn responses_dashscope_rules_match_python_fixture() {
        let fixture = fixture();
        let (mapped, metadata) =
            anthropic_to_openai(&fixture["dashscope_request"], "gpt-5.2", true).unwrap();
        assert_eq!(mapped, fixture["dashscope_mapped"]);
        assert_eq!(
            metadata.rule_ids,
            vec![
                "tool.dashscope.responses.web_search-drop".to_string(),
                "provider.dashscope.responses-tools-cap".to_string(),
            ]
        );
    }

    #[test]
    fn dashscope_responses_host_contract_matches_python_fixture() {
        let fixture = fixture();
        for case in fixture["dashscope_host_cases"].as_array().unwrap() {
            let actual = is_dashscope_responses_endpoint(
                case["provider"].as_str().unwrap(),
                case["url"].as_str().unwrap(),
            );
            assert_eq!(
                actual,
                case["matches"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn responses_response_mapping_matches_python_fixture() {
        let fixture = fixture();
        let mapped = openai_to_anthropic(&fixture["response"], "claude-opus-4-8");
        assert_eq!(mapped, fixture["anthropic"]);
    }

    #[test]
    fn responses_incomplete_maps_to_max_tokens() {
        let mapped = openai_to_anthropic(
            &json!({
                "id": "resp_incomplete",
                "status": "incomplete",
                "output_text": "partial",
                "usage": {},
            }),
            "claude-opus-4-8",
        );
        assert_eq!(mapped["stop_reason"], "max_tokens");
        assert_eq!(
            mapped["content"],
            json!([{"type": "text", "text": "partial"}])
        );
    }

    #[test]
    fn responses_tool_result_object_uses_python_json_spacing() {
        let (mapped, _metadata) = anthropic_to_openai(
            &json!({
                "model": "claude-opus-4-8",
                "messages": [{
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "call_1",
                        "content": {"ok": true, "items": [1, 2]},
                    }],
                }],
            }),
            "gpt-5.2",
            false,
        )
        .unwrap();
        assert_eq!(
            mapped["input"][0],
            json!({
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "{\"ok\": true, \"items\": [1, 2]}",
            })
        );
    }
}
