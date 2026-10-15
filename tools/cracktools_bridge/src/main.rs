// Local JSON wrapper; algorithm and node execution code comes from upstream.
mod commands;
mod crypto;
mod encoding;
mod hash;
mod text;

use std::io::{self, Read};
use serde::Deserialize;
use serde_json::{json, Value};
use commands::{NodeData, WorkflowNode, WorkflowEdge};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step { algorithm: String, mode: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { input: String, steps: Vec<Step> }

fn node(id: &str, category: &str, value: Option<String>, algorithm: Option<String>, mode: Option<String>) -> WorkflowNode {
    WorkflowNode { id: id.into(), node_type: category.into(), data: NodeData {
        label: id.into(), category: category.into(), status: "idle".into(),
        value, algorithm, mode, result: None, error: None } }
}

fn execute(request: Request) -> Result<Value, String> {
    if request.input.len() > 32768 || request.steps.is_empty() || request.steps.len() > 16 {
        return Err("input must be <= 32 KiB and steps must be 1..16".into());
    }
    let mut current = request.input;
    let mut trace = Vec::new();
    let mut total = 0;
    for step in request.steps {
        if step.mode != "encode" && step.mode != "decode" { return Err("invalid mode".into()); }
        let input_bytes = current.len();
        let result = commands::execute_workflow(vec![
            node("input", "input", Some(current), None, None),
            node("operation", "encoding", None, Some(step.algorithm.clone()), Some(step.mode.clone())),
            node("output", "output", None, None, None)], vec![
            WorkflowEdge { id: "a".into(), source: "input".into(), target: "operation".into() },
            WorkflowEdge { id: "b".into(), source: "operation".into(), target: "output".into() }]);
        let operation = result.nodes.iter().find(|node| node.id == "operation").ok_or("operation missing")?;
        if operation.data.status != "success" || operation.data.error.is_some() {
            return Ok(json!({"ok": false, "error": operation.data.error, "failed_step": trace.len(), "steps": trace}));
        }
        current = operation.data.result.clone().ok_or("output missing")?;
        total += current.len();
        if current.len() > 131072 || total > 524288 { return Err("workflow output budget exceeded".into()); }
        trace.push(json!({"algorithm": step.algorithm, "mode": step.mode, "input_bytes": input_bytes,
                          "output_bytes": current.len(), "output": current}));
    }
    Ok(json!({"ok": true, "output": current, "steps": trace}))
}

fn main() {
    let mut raw = String::new();
    let result = io::stdin().take(65537).read_to_string(&mut raw)
        .map_err(|error| error.to_string())
        .and_then(|_| if raw.len() > 65536 { Err("request too large".into()) } else { Ok(()) })
        .and_then(|_| serde_json::from_str::<Request>(&raw).map_err(|error| error.to_string()))
        .and_then(execute);
    match result {
        Ok(output) => { println!("{}", output); if output["ok"] != true { std::process::exit(1); } },
        Err(error) => { println!("{}", json!({"ok": false, "error": error})); std::process::exit(1); }
    }
}
