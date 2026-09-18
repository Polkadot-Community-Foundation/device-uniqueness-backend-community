// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use serde_json::{Map, Value};
use utoipa::OpenApi;

pub const DOCS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api-reference");

/// Path to the hand-authored template with the `@NAV`/`@ENDPOINTS` placeholders.
pub fn template_path() -> String {
    format!("{DOCS_DIR}/template.html")
}

pub fn openapi_json_path() -> String {
    format!("{DOCS_DIR}/openapi.json")
}

pub fn index_html_path() -> String {
    format!("{DOCS_DIR}/index.html")
}

pub fn merged_doc() -> Value {
    let mut base = serde_json::to_value(device_attestation::openapi::ApiDoc::openapi())
        .expect("device-attestation doc");
    let indexer =
        serde_json::to_value(username_indexer::openapi::ApiDoc::openapi()).expect("indexer doc");
    #[cfg(invite_tickets)]
    let invites =
        serde_json::to_value(invite_tickets::openapi::ApiDoc::openapi()).expect("invites doc");
    let turn = serde_json::to_value(turn::openapi::ApiDoc::openapi()).expect("turn doc");
    let notify =
        serde_json::to_value(notifications::openapi::ApiDoc::openapi()).expect("notify doc");

    let others = [
        &indexer,
        #[cfg(invite_tickets)]
        &invites,
        &turn,
        &notify,
    ];
    for other in others {
        merge_object(&mut base, other, "/paths");
        merge_object(&mut base, other, "/components/schemas");
        merge_array(&mut base, other, "/tags");
    }
    base
}

pub fn openapi_json() -> String {
    let mut out = serde_json::to_string_pretty(&merged_doc()).expect("serialize openapi");
    out.push('\n');
    out
}

pub fn index_html() -> anyhow::Result<String> {
    let template = std::fs::read_to_string(template_path())?;
    let doc = merged_doc();
    let nav = render_nav(&doc);
    let endpoints = render_endpoints(&doc);
    Ok(template
        .replace("<!--@NAV-->", &nav)
        .replace("<!--@ENDPOINTS-->", &endpoints))
}

fn merge_object(base: &mut Value, other: &Value, path: &str) {
    let src = other
        .pointer(path)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    base.pointer_mut(path)
        .and_then(Value::as_object_mut)
        .expect("merge target is an object")
        .extend(src);
}

fn merge_array(base: &mut Value, other: &Value, path: &str) {
    let src = other
        .pointer(path)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if src.is_empty() {
        return;
    }
    base.pointer_mut(path)
        .and_then(Value::as_array_mut)
        .expect("merge target is an array")
        .extend(src);
}

struct Endpoint<'a> {
    method: &'a str,
    path: &'a str,
    op: &'a Map<String, Value>,
}

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

fn endpoints_by_tag(doc: &Value) -> Vec<(String, Vec<Endpoint<'_>>)> {
    let mut tag_order: Vec<String> = doc
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut grouped: Vec<(String, Vec<Endpoint<'_>>)> = Vec::new();
    let paths = doc.get("paths").and_then(Value::as_object);
    if let Some(paths) = paths {
        for (path, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            for method in METHODS {
                let Some(op) = item.get(method).and_then(Value::as_object) else {
                    continue;
                };
                let tag = op
                    .get("tags")
                    .and_then(Value::as_array)
                    .and_then(|t| t.first())
                    .and_then(Value::as_str)
                    .unwrap_or("Other")
                    .to_string();
                if !tag_order.contains(&tag) {
                    tag_order.push(tag.clone());
                }
                let endpoint = Endpoint { method, path, op };
                match grouped.iter_mut().find(|(t, _)| *t == tag) {
                    Some((_, list)) => list.push(endpoint),
                    None => grouped.push((tag, vec![endpoint])),
                }
            }
        }
    }
    grouped.sort_by_key(|(tag, _)| {
        tag_order
            .iter()
            .position(|t| t == tag)
            .unwrap_or(usize::MAX)
    });
    grouped
}

fn render_nav(doc: &Value) -> String {
    let mut out = String::new();
    for (tag, list) in endpoints_by_tag(doc) {
        out.push_str("    <div class=\"nav-section\">\n");
        out.push_str(&format!(
            "      <div class=\"nav-section-title\">{}</div>\n",
            escape(&tag)
        ));
        for ep in list {
            out.push_str(&format!(
                "      <a class=\"nav-item {cls}\" href=\"javascript:void(0)\" data-scroll-to=\"{id}\"><span class=\"method-mini\">{m}</span><span class=\"path\">{path}</span></a>\n",
                cls = method_class(ep.method),
                id = endpoint_id(ep.path),
                m = ep.method.to_uppercase(),
                path = escape(&nav_path(ep.path)),
            ));
        }
        out.push_str("    </div>\n\n");
    }
    out.trim_end().to_string()
}

fn nav_path(path: &str) -> String {
    path.strip_prefix("/api/v1").unwrap_or(path).to_string()
}

fn render_endpoints(doc: &Value) -> String {
    let mut out = String::new();
    for (i, (tag, list)) in endpoints_by_tag(doc).into_iter().enumerate() {
        let num = i + 2; // hero = 00, flow = 01, generated sections start at 02
        let first_id = list
            .first()
            .map(|ep| endpoint_id(ep.path))
            .unwrap_or_default();
        out.push_str("    <section class=\"section\">\n");
        out.push_str("      <div class=\"section-header\">\n");
        out.push_str(&format!(
            "        <span class=\"section-num\">{num:02}</span>\n"
        ));
        out.push_str(&format!("        <h2>{}</h2>\n", escape(&tag)));
        out.push_str(&format!(
            "        <a class=\"section-anchor\" href=\"javascript:void(0)\" data-scroll-to=\"{first_id}\">#</a>\n"
        ));
        out.push_str("      </div>\n\n");
        for ep in &list {
            out.push_str(&render_endpoint(doc, ep));
            out.push('\n');
        }
        out.push_str("    </section>\n\n");
    }
    out.trim_end().to_string()
}

fn render_endpoint(doc: &Value, ep: &Endpoint<'_>) -> String {
    let id = endpoint_id(ep.path);
    let secured = ep.op.get("security").is_some();
    let params = ep.op.get("parameters").and_then(Value::as_array);
    let responses = sorted_responses(ep.op);

    let mut meta = String::new();
    for (code, _) in &responses {
        meta.push_str(&format!(
            "            <span class=\"chip {}\">{}</span>\n",
            chip_class(code),
            code
        ));
    }
    meta.push_str(if secured {
        "            <span class=\"chip blue\">bearer JWT</span>\n"
    } else {
        "            <span class=\"chip\">public</span>\n"
    });

    let mut body = String::new();
    if let Some(desc) = operation_text(ep.op) {
        body.push_str(&format!(
            "          <p class=\"endpoint-desc\">{}</p>\n",
            markdown_lite(&desc)
        ));
    }
    if secured {
        body.push_str("          <div class=\"auth-note\">\n            <span class=\"auth-label\">Auth</span>\n            <span class=\"auth-text\">Bearer JWT required in the <code>Authorization</code> header.</span>\n          </div>\n");
    }
    body.push_str(&render_param_tables(params));
    body.push_str(&render_request_body_tables(doc, ep.op));
    if let Some(example) = request_example(doc, ep.op) {
        body.push_str(&code_block("Request Body", &highlight(&example, 0)));
    }
    for (code, resp) in &responses {
        if let Some(example) = content_example(doc, resp) {
            body.push_str(&code_block(
                &format!("Response · {code} · application/json"),
                &highlight(&example, 0),
            ));
        }
    }
    body.push_str(&render_status_grid(doc, &responses));

    format!(
        "      <div class=\"endpoint\" id=\"{id}\">\n\
         \x20       <div class=\"endpoint-head\">\n\
         \x20         <div class=\"endpoint-title\">\n\
         \x20           <span class=\"method-badge {mcls}\">{method}</span>\n\
         \x20           <span class=\"endpoint-path\">{path}</span>\n\
         \x20         </div>\n\
         \x20         <div class=\"endpoint-meta\">\n{meta}          </div>\n\
         \x20       </div>\n\
         \x20       <div class=\"endpoint-body\">\n{body}        </div>\n\
         \x20     </div>\n",
        mcls = method_class(ep.method),
        method = ep.method.to_uppercase(),
        path = endpoint_path_html(ep),
    )
}

fn endpoint_path_html(ep: &Endpoint<'_>) -> String {
    let mut html = escape(ep.path);
    let queries: Vec<String> = ep
        .op
        .get("parameters")
        .and_then(Value::as_array)
        .map(|params| {
            params
                .iter()
                .filter(|p| p.get("in").and_then(Value::as_str) == Some("query"))
                .filter_map(|p| p.get("name").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if !queries.is_empty() {
        let mut q = String::from("<span class=\"query\">");
        for (i, name) in queries.iter().enumerate() {
            let sep = if i == 0 { '?' } else { '&' };
            q.push_str(&format!(
                "{sep}{name}=<span class=\"pname\">&lt;{name}&gt;</span>",
                name = escape(name)
            ));
        }
        q.push_str("</span>");
        html.push_str(&q);
    }
    html
}

fn render_param_tables(params: Option<&Vec<Value>>) -> String {
    let Some(params) = params else {
        return String::new();
    };
    let mut out = String::new();
    for (kind, label) in [("header", "Header"), ("query", "Query"), ("path", "Path")] {
        let rows: Vec<TableRow> = params
            .iter()
            .filter(|p| p.get("in").and_then(Value::as_str) == Some(kind))
            .map(|p| TableRow {
                name: p
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                ty: type_label(p.get("schema")),
                required: p.get("required").and_then(Value::as_bool).unwrap_or(false),
                desc: p
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            })
            .collect();
        out.push_str(&param_table(label, &rows));
    }
    out
}

fn render_request_body_tables(doc: &Value, op: &Map<String, Value>) -> String {
    let Some(schema) = op
        .get("requestBody")
        .and_then(|rb| rb.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
    else {
        return String::new();
    };
    let Some(object) = resolve_object_schema(doc, schema, 0) else {
        return String::new();
    };
    let mut out = object_table(&object, "Field");
    if let Some(props) = object.get("properties").and_then(Value::as_object) {
        for (name, prop) in props {
            if let Some(nested) = resolve_object_schema(doc, prop, 0) {
                out.push_str(&object_table(&nested, &format!("{name}.*")));
            }
        }
    }
    out
}

struct TableRow {
    name: String,
    ty: String,
    required: bool,
    desc: String,
}

fn object_table(object: &Value, label: &str) -> String {
    let Some(props) = object.get("properties").and_then(Value::as_object) else {
        return String::new();
    };
    let required: Vec<&str> = object
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let rows: Vec<TableRow> = props
        .iter()
        .map(|(name, prop)| TableRow {
            name: name.clone(),
            ty: type_label(Some(prop)),
            required: required.contains(&name.as_str()),
            desc: prop
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
        .collect();
    param_table(label, &rows)
}

fn param_table(label: &str, rows: &[TableRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "          <div class=\"tbl-wrap\">\n            <table class=\"params\">\n              <thead>\n",
    );
    out.push_str(&format!(
        "                <tr><th>{label}</th><th>Type</th><th>Required</th><th>Description</th></tr>\n",
        label = escape(label)
    ));
    out.push_str("              </thead>\n              <tbody>\n");
    for row in rows {
        let (req_cls, req_txt) = if row.required {
            ("req yes", "yes")
        } else {
            ("req", "no")
        };
        out.push_str(&format!(
            "                <tr><td class=\"name\">{name}</td><td class=\"type\">{ty}</td><td class=\"{req_cls}\">{req_txt}</td><td class=\"desc\">{desc}</td></tr>\n",
            name = escape(&row.name),
            ty = escape(&row.ty),
            desc = markdown_lite(&row.desc),
        ));
    }
    out.push_str("              </tbody>\n            </table>\n          </div>\n");
    out
}

fn resolve_ref<'a>(doc: &'a Value, schema: &Value) -> Option<&'a Value> {
    let reference = schema.get("$ref").and_then(Value::as_str)?;
    let name = reference.rsplit('/').next()?;
    doc.pointer(&format!("/components/schemas/{name}"))
}

fn resolve_object_schema(doc: &Value, schema: &Value, depth: u8) -> Option<Value> {
    if depth > 6 {
        return None;
    }
    if let Some(target) = resolve_ref(doc, schema) {
        return resolve_object_schema(doc, target, depth + 1);
    }
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        for sub in branches {
            if is_null_schema(sub) {
                continue;
            }
            if let Some(resolved) = resolve_object_schema(doc, sub, depth + 1) {
                return Some(resolved);
            }
        }
    }
    if schema.get("properties").is_some() {
        return Some(schema.clone());
    }
    None
}

fn render_status_grid(doc: &Value, responses: &[(String, &Value)]) -> String {
    if responses.is_empty() {
        return String::new();
    }
    let mut out = String::from("          <div class=\"status-grid\">\n");
    for (code, resp) in responses {
        let example = content_example(doc, resp);
        let label = status_label(code, example.as_ref());
        let desc = resp
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        out.push_str(
            "            <div class=\"status-card\">\n              <div class=\"sc-head\">\n",
        );
        out.push_str(&format!(
            "                <span class=\"sc-code c{code}\">{code}</span>\n                <span class=\"sc-label\">{label}</span>\n",
            label = escape(&label)
        ));
        out.push_str(&format!(
            "              </div>\n              <div class=\"sc-desc\">{}</div>\n            </div>\n",
            markdown_lite(desc)
        ));
    }
    out.push_str("          </div>\n");
    out
}

fn code_block(label: &str, pre: &str) -> String {
    format!(
        "          <div class=\"code-block\">\n            <div class=\"code-head\">\n              <span class=\"code-head-label\">{label}</span>\n              <div class=\"code-head-right\"><span class=\"code-lang-tag\">json</span></div>\n            </div>\n<pre>{pre}</pre>\n          </div>\n",
        label = escape(label),
    )
}

fn sorted_responses(op: &Map<String, Value>) -> Vec<(String, &Value)> {
    let mut responses: Vec<(String, &Value)> = op
        .get("responses")
        .and_then(Value::as_object)
        .map(|r| r.iter().map(|(k, v)| (k.clone(), v)).collect())
        .unwrap_or_default();
    responses.sort_by_key(|(code, _)| code.parse::<u16>().unwrap_or(u16::MAX));
    responses
}

fn request_example(doc: &Value, op: &Map<String, Value>) -> Option<Value> {
    op.get("requestBody")
        .and_then(|rb| content_example(doc, rb))
}

fn content_example(doc: &Value, node: &Value) -> Option<Value> {
    let json = node
        .get("content")
        .and_then(|c| c.get("application/json"))?;
    if let Some(example) = json.get("example") {
        return Some(example.clone());
    }
    example_from_schema(doc, json.get("schema")?, 0)
}

fn example_from_schema(doc: &Value, schema: &Value, depth: u8) -> Option<Value> {
    if depth > 8 {
        return None;
    }
    if let Some(example) = schema.get("example") {
        return Some(example.clone());
    }
    if let Some(target) = resolve_ref(doc, schema) {
        return example_from_schema(doc, target, depth + 1);
    }
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        for sub in branches {
            if is_null_schema(sub) {
                continue;
            }
            if let Some(value) = example_from_schema(doc, sub, depth + 1) {
                return Some(value);
            }
        }
    }
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        let mut obj = Map::new();
        for (key, prop) in props {
            let value = example_from_schema(doc, prop, depth + 1).unwrap_or(Value::Null);
            obj.insert(key.clone(), value);
        }
        return Some(Value::Object(obj));
    }
    None
}

fn is_null_schema(schema: &Value) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("null")
}

fn operation_text(op: &Map<String, Value>) -> Option<String> {
    op.get("description")
        .or_else(|| op.get("summary"))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}

fn status_label(code: &str, example: Option<&Value>) -> String {
    if let Some(err) = example.and_then(|e| e.get("error")).and_then(Value::as_str) {
        return err.to_string();
    }
    match code {
        "200" => "OK",
        "201" => "CREATED",
        "202" => "ACCEPTED",
        "204" => "NO_CONTENT",
        "400" => "WRONG_DATA",
        "401" => "UNAUTHORIZED",
        "403" => "FORBIDDEN",
        "404" => "NOT_FOUND",
        "409" => "CONFLICT",
        "429" => "RATE_LIMITED",
        "500" => "INTERNAL",
        "503" => "UNAVAILABLE",
        other => other,
    }
    .to_string()
}

fn chip_class(code: &str) -> &'static str {
    match code {
        c if c.starts_with('2') => "green",
        "409" => "blue",
        "429" => "yellow",
        c if c.starts_with('4') || c.starts_with('5') => "red",
        _ => "",
    }
}

fn method_class(method: &str) -> String {
    format!("m-{method}")
}

fn endpoint_id(path: &str) -> String {
    let mut slug = String::from("ep-");
    let mut prev_dash = false;
    for ch in path.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    slug.trim_matches('-').replace("ep--", "ep-")
}

fn type_label(schema: Option<&Value>) -> String {
    let Some(schema) = schema else {
        return "string".to_string();
    };
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference.rsplit('/').next().unwrap_or("object").to_string();
    }
    let ty = match schema.get("type") {
        // OpenAPI 3.1 nullable types serialize as e.g. ["string", "null"].
        Some(Value::Array(types)) => types
            .iter()
            .filter_map(Value::as_str)
            .find(|t| *t != "null"),
        Some(Value::String(t)) => Some(t.as_str()),
        _ => None,
    };
    match ty {
        Some("array") => format!("{}[]", type_label(schema.get("items"))),
        Some("integer") => "number".to_string(),
        Some(other) => other.to_string(),
        None => "object".to_string(),
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn markdown_lite(text: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for (i, segment) in text.split('`').enumerate() {
        if i > 0 {
            in_code = !in_code;
        }
        if in_code {
            out.push_str(&format!("<code>{}</code>", escape(segment)));
        } else {
            out.push_str(&escape(segment));
        }
    }
    out
}

fn highlight(value: &Value, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    let child = "  ".repeat(indent + 1);
    match value {
        Value::Null => "<span class=\"k\">null</span>".to_string(),
        Value::Bool(b) => format!("<span class=\"k\">{b}</span>"),
        Value::Number(n) => format!("<span class=\"n\">{n}</span>"),
        Value::String(s) => format!("<span class=\"s\">\"{}\"</span>", escape(s)),
        Value::Array(items) => {
            if items.is_empty() {
                return "<span class=\"p\">[]</span>".to_string();
            }
            let mut out = String::from("<span class=\"p\">[</span>\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&child);
                out.push_str(&highlight(item, indent + 1));
                if i + 1 < items.len() {
                    out.push_str("<span class=\"p\">,</span>");
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push_str("<span class=\"p\">]</span>");
            out
        }
        Value::Object(map) => {
            if map.is_empty() {
                return "<span class=\"p\">{}</span>".to_string();
            }
            let mut out = String::from("<span class=\"p\">{</span>\n");
            for (i, (key, val)) in map.iter().enumerate() {
                out.push_str(&child);
                out.push_str(&format!(
                    "<span class=\"s\">\"{}\"</span><span class=\"p\">:</span> ",
                    escape(key)
                ));
                out.push_str(&highlight(val, indent + 1));
                if i + 1 < map.len() {
                    out.push_str("<span class=\"p\">,</span>");
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push_str("<span class=\"p\">}</span>");
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_stable_and_clean() {
        assert_eq!(endpoint_id("/healthcheck"), "ep-healthcheck");
        assert_eq!(
            endpoint_id("/.well-known/jwks.json"),
            "ep-well-known-jwks-json"
        );
        assert_eq!(
            endpoint_id("/api/v1/auth/token/refresh"),
            "ep-api-v1-auth-token-refresh"
        );
    }

    #[test]
    fn merged_doc_has_every_route_and_the_security_scheme() {
        let doc = merged_doc();
        let paths = doc.get("paths").and_then(Value::as_object).unwrap();
        for route in [
            "/healthcheck",
            "/livez",
            "/readyz",
            "/.well-known/jwks.json",
            "/api/v1/attester",
            "/api/v1/auth/challenges",
            "/api/v1/auth/token",
            "/api/v1/usernames",
            "/api/v1/usernames/available",
            "/api/v1/usernames/search",
            #[cfg(invite_tickets)]
            "/api/v1/invitation-ticket/claim",
            "/api/v1/turn/issue",
            "/api/v1/notify",
        ] {
            assert!(paths.contains_key(route), "missing route {route}");
        }
        assert!(doc
            .pointer("/components/securitySchemes/bearer_jwt")
            .is_some());
    }

    #[test]
    fn availability_documents_the_v1_shape_and_internal_failure() {
        let doc = merged_doc();
        let responses = doc
            .pointer("/paths/~1api~1v1~1usernames~1available/post/responses")
            .and_then(Value::as_object)
            .expect("availability responses");
        assert!(responses.contains_key("500"));

        let schema = responses
            .get("200")
            .and_then(|response| response.pointer("/content/application~1json/schema/$ref"))
            .and_then(Value::as_str)
            .expect("availability response schema ref");
        assert_eq!(schema, "#/components/schemas/AvailableV1Response");
        assert!(doc
            .pointer("/components/schemas/AvailableV1Response/properties/_tag")
            .is_some());
    }

    #[test]
    #[cfg_attr(
        not(invite_tickets),
        ignore = "the committed reference documents every surface, invite-tickets included"
    )]
    fn committed_artifacts_are_in_sync() {
        let want_json = std::fs::read_to_string(openapi_json_path()).expect("read openapi.json");
        assert_eq!(
            want_json,
            openapi_json(),
            "openapi.json is stale — run `just openapi`"
        );

        let want_html = std::fs::read_to_string(index_html_path()).expect("read index.html");
        assert_eq!(
            want_html,
            index_html().expect("render html"),
            "index.html is stale — run `just openapi`"
        );
    }
}
