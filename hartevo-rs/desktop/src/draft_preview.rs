//! Readable presentation of persisted model drafts; source bytes stay unchanged.

use dioxus::prelude::*;
use hartevo_application::WorkProductProjection;
use serde_json::Value;

pub(crate) fn product_title(product: &WorkProductProjection) -> &str {
    match (product.work_product_type.as_str(), product.title.as_str()) {
        (
            "runtime_draft",
            "Cordis draft · requires human review" | "Runtime draft · requires human review",
        ) => "内容草稿",
        _ => &product.title,
    }
}

fn structured_draft(text: &str) -> Option<Value> {
    // Oversized/nested documents keep the original text instead of expanding a huge UI tree.
    fn fits(value: &Value, depth: usize, remaining: &mut usize) -> bool {
        if depth > 12 || *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        match value {
            Value::Object(fields) => fields.values().all(|v| fits(v, depth + 1, remaining)),
            Value::Array(items) => items.iter().all(|v| fits(v, depth + 1, remaining)),
            _ => true,
        }
    }
    let text = text.trim();
    let json = text
        .strip_prefix("```json\n")
        .or_else(|| text.strip_prefix("```\n"))
        .and_then(|body| body.strip_suffix("```"))
        .unwrap_or(text);
    let value: Value = serde_json::from_str(json).ok()?;
    value.as_object()?.get("draft")?;
    fits(&value, 0, &mut 512).then_some(value)
}

fn field_label(key: &str) -> &str {
    match key {
        "draft" => "草稿内容",
        "posts" => "社媒文案",
        "copy" | "text" | "body" | "content" => "正文",
        "visual_suggestion" | "visualSuggestion" => "画面建议",
        "status" => "说明",
        "uncertainty" | "uncertainties" => "待核实与不确定项",
        "assumptions" => "假设",
        "constraints" => "约束",
        "title" => "标题",
        "subject" => "主题",
        "notes" => "备注",
        _ => key,
    }
}

fn render_value(value: &Value) -> Element {
    match value {
        Value::Object(fields) if !fields.is_empty() => rsx! {
            dl { class: "draft-fields",
                for (key, value) in fields {
                    div { key: "{key}", class: "draft-field",
                        dt { "{field_label(key)}" }
                        dd { {render_value(value)} }
                    }
                }
            }
        },
        Value::Array(items) if !items.is_empty() => rsx! {
            ol { class: "draft-items",
                for (index, value) in items.iter().enumerate() {
                    li { key: "{index}", {render_value(value)} }
                }
            }
        },
        Value::String(text) => rsx! { p { "{text}" } },
        _ => rsx! { p { "{value}" } },
    }
}

pub(crate) fn excerpt(text: &str) -> String {
    fn first_text(value: &Value) -> Option<&str> {
        match value {
            Value::String(text) if !text.trim().is_empty() => Some(text),
            Value::Array(items) => items.iter().find_map(first_text),
            Value::Object(fields) => ["copy", "text", "body", "content", "posts", "draft"]
                .into_iter()
                .find_map(|key| fields.get(key).and_then(first_text)),
            _ => None,
        }
    }
    structured_draft(text)
        .and_then(|value| first_text(value.get("draft")?).map(str::to_owned))
        .unwrap_or_else(|| text.to_owned())
}

#[component]
pub(crate) fn DraftPreview(text: String) -> Element {
    if let Some(value) = structured_draft(&text) {
        rsx! {
            div { class: "draft-preview",
                {render_value(&value)}
                details { class: "draft-original",
                    summary { "查看原始内容" }
                    pre { "{text}" }
                }
            }
        }
    } else {
        rsx! { div { class: "draft-preview", p { "{text}" } } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_preview_keeps_all_fields_and_escapes_model_markup() {
        fn inspect(node: &VNode, dom: &VirtualDom, output: &mut String) {
            use dioxus::dioxus_core::DynamicNode;
            use std::fmt::Write as _;
            write!(output, "{:?} {:?}", node.template, node.dynamic_attrs).unwrap();
            for (index, child) in node.dynamic_nodes.iter().enumerate() {
                match child {
                    DynamicNode::Component(component) => {
                        if let Some(scope) = component.mounted_scope(index, node, dom) {
                            inspect(scope.root_node(), dom, output);
                        }
                    }
                    DynamicNode::Fragment(children) => {
                        for child in children {
                            inspect(child, dom, output);
                        }
                    }
                    DynamicNode::Text(text) => output.push_str(&text.value),
                    DynamicNode::Placeholder(_) => {}
                }
            }
        }
        let body = r#"{"draft":{"posts":[{"copy":"First post <script>alert(1)</script>","visual_suggestion":"Blue bottle"},{"copy":"Second post"}]},"uncertainty":["Weight not verified"],"extra":{"custom_key":"Retain this", "flag":false}}"#;
        let mut dom = VirtualDom::new_with_props(
            DraftPreview,
            DraftPreviewProps {
                text: body.to_owned(),
            },
        );
        let mutations = dom.rebuild_to_vec();
        let mut rendered = format!("{mutations:?}");
        inspect(dom.base_scope().root_node(), &dom, &mut rendered);
        for expected in [
            "First post",
            "Second post",
            "画面建议",
            "Blue bottle",
            "待核实与不确定项",
            "Weight not verified",
            "custom_key",
            "Retain this",
            "false",
            "查看原始内容",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
        assert!(rendered.contains("First post <script>alert(1)</script>"));
        assert!(!rendered.contains("dangerous_inner_html"));
        assert_eq!(excerpt(body), "First post <script>alert(1)</script>");
    }

    #[test]
    fn plain_truncated_and_unrelated_json_keep_their_original_content() {
        for body in [
            "Plain draft\nSecond line",
            r#"{"draft":{"posts":["unfinished""#,
            r#"{"status":"accepted"}"#,
        ] {
            assert!(structured_draft(body).is_none());
            assert_eq!(excerpt(body), body);
        }
        let fenced = "```json\n{\"draft\":\"Draft copy\",\"uncertainty\":[]}\n```";
        assert_eq!(excerpt(fenced), "Draft copy");
        let oversized = serde_json::json!({"draft": vec!["item"; 600]}).to_string();
        assert!(structured_draft(&oversized).is_none());
    }
}
