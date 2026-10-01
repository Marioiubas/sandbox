//! The relay's decisions without I/O: what reaches the server, what reaches
//! the agent, and what is logged (MCP Guard, ADR-030).

use super::*;
use crate::pipeline::Stats;
use audit::{AuditEvent, ChainHash, DecisionResult, Recorder, SessionId};
use netguard::ingress::ChannelAuth;
use netguard::resolver::StaticResolver;
use policy::EgressPolicy;
use proptest::prelude::*;
use std::sync::Mutex;

#[derive(Default)]
struct Mem(Mutex<Vec<AuditEvent>>);

impl Recorder for Mem {
    fn append(&self, ev: &AuditEvent) -> anyhow::Result<ChainHash> {
        self.0.lock().unwrap().push(ev.clone());
        Ok(ChainHash([0; 32]))
    }
}

const POLICY: &str = r#"
version = 1
[mcp.gh]
command = ["/usr/bin/true"]
tools.write = ["post"]
tools.untrusted = ["read"]
tools.deny = ["merge"]
"#;

struct Fx {
    ctx: Arc<PipelineCtx>,
    cfg: McpServerConfig,
    rec: Arc<Mem>,
}

fn fx() -> Fx {
    let p = policy::config::parse_policy_str(POLICY).unwrap();
    let policy = EgressPolicy::compile([("user", p.egress.as_slice())]).unwrap().with_mcp(&p.mcp).unwrap();
    let rec = Arc::new(Mem::default());
    let session = SessionId::new();
    let ctx = Arc::new(PipelineCtx {
        labels_session: session.clone(),
        session,
        enduser: "local:test".into(),
        groups: vec![],
        agent: "probe".into(),
        agent_sha256: None,
        task: None,
        sandbox: "test".into(),
        policy: Arc::new(policy),
        resolver: Arc::new(StaticResolver::default()),
        recorder: rec.clone(),
        auth: ChannelAuth::Implicit,
        stats: Arc::new(Stats::default()),
        connect_timeout: Duration::from_secs(1),
        sni_timeout: Duration::from_secs(1),
        l7: None,
        shadow: None,
        mcp: None,
        approvals: Default::default(),
    });
    Fx { ctx, cfg: p.mcp["gh"].clone(), rec }
}

fn manifest() -> Manifest {
    let tool = |n: &str| json!({"name": n, "description": format!("{n} tool"), "inputSchema": {"type": "object"}});
    mcpguard::manifest::manifest(vec![tool("read"), tool("post"), tool("merge")]).unwrap()
}

fn relay<'a>(f: &'a Fx, pin: Pin) -> Relay<'a> {
    Relay {
        ctx: &f.ctx,
        name: "gh",
        cfg: &f.cfg,
        dest: Dest::default(),
        server_session: "server".into(),
        pin,
        init: json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}),
        pending: HashSet::new(),
        relist: None,
        relists: 0,
    }
}

fn frame(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap()
}

fn call(id: i64, tool: &str) -> Vec<u8> {
    frame(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}}))
}

fn reason(reply: &Option<Value>) -> Option<String> {
    reply.as_ref()?.pointer("/error/data/reason")?.as_str().map(str::to_string)
}

#[test]
fn a_granted_call_is_logged_then_forwarded_and_only_its_reply_comes_back() {
    let f = fx();
    let mut r = relay(&f, Pin::Pinned(manifest()));
    let (to_agent, to_server) = r.on_agent(&call(7, "read"));
    assert!(to_agent.is_none());
    assert_eq!(to_server.unwrap()["params"]["name"], "read");
    let evs = f.rec.0.lock().unwrap().clone();
    let allow = evs.iter().find(|e| e.kind == EventKind::RequestDecision).expect("write-ahead row");
    assert_eq!(allow.decision.as_ref().unwrap().result, DecisionResult::Allow);
    // The untrusted tool raised its label.
    assert!(f.ctx.policy.labels().snapshot().untrusted_input);
    // Its reply goes back once; an unknown or repeated id does not.
    let reply = frame(json!({"jsonrpc": "2.0", "id": 7, "result": {"content": []}}));
    assert!(r.on_server(&reply).0.is_some());
    assert!(r.on_server(&reply).0.is_none(), "a second reply to the same id is dropped");
    let stray = frame(json!({"jsonrpc": "2.0", "id": 8, "result": {}}));
    assert!(r.on_server(&stray).0.is_none(), "a reply to nothing the agent asked is dropped");
    // A write tool raises external_effect.
    let (_, to_server) = r.on_agent(&call(9, "post"));
    assert!(to_server.is_some());
    assert!(f.ctx.policy.labels().snapshot().external_effect);
}

#[test]
fn what_is_not_granted_or_not_strict_is_refused_and_logged() {
    let f = fx();
    let mut r = relay(&f, Pin::Pinned(manifest()));
    for (bytes, want) in [
        (call(1, "merge"), "mcp_tool_not_allowed"),
        (call(2, "nope"), "mcp_tool_unknown"),
        (
            frame(
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read", "arguments": []}}),
            ),
            "mcp_malformed",
        ),
        (frame(json!({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {}})), "mcp_method_not_allowed"),
        (b"{\"jsonrpc\": \"2.0\", \"id\": 5, \"method\": ".to_vec(), "mcp_malformed"),
    ] {
        let (to_agent, to_server) = r.on_agent(&bytes);
        assert!(to_server.is_none(), "{want}: nothing reaches the server");
        if want != "mcp_malformed" || to_agent.is_some() {
            assert_eq!(reason(&to_agent).as_deref(), Some(want));
        }
    }
    let denies = f.rec.0.lock().unwrap().iter().filter(|e| e.reason.is_some()).count();
    assert_eq!(denies, 5, "every refusal is logged with a reason");
    // Answered from the pinned state, never forwarded.
    let (to_agent, to_server) = r.on_agent(&frame(json!({"jsonrpc": "2.0", "id": 6, "method": "tools/list"})));
    assert!(to_server.is_none());
    assert_eq!(to_agent.unwrap()["result"]["tools"].as_array().unwrap().len(), 3);
}

#[test]
fn an_unapproved_server_relays_nothing() {
    let f = fx();
    let mut r = relay(&f, Pin::Unapproved(manifest()));
    for m in ["initialize", "tools/list", "tools/call", "ping"] {
        let (to_agent, to_server) = r.on_agent(&frame(
            json!({"jsonrpc": "2.0", "id": 1, "method": m, "params": {"name": "read", "arguments": {}}}),
        ));
        assert!(to_server.is_none(), "{m}");
        assert_eq!(reason(&to_agent).as_deref(), Some("mcp_manifest_unapproved"), "{m}");
    }
    let cancel = frame(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}));
    assert_eq!(r.on_agent(&cancel), (None, None), "not even a cancellation reaches an unapproved server");
}

#[test]
fn server_to_client_requests_are_refused_never_relayed() {
    let f = fx();
    let mut r = relay(&f, Pin::Pinned(manifest()));
    for m in ["sampling/createMessage", "roots/list", "elicitation/create"] {
        let (to_agent, to_server) = r.on_server(&frame(json!({"jsonrpc": "2.0", "id": 5, "method": m, "params": {}})));
        assert!(to_agent.is_none(), "{m} never reaches the agent");
        assert_eq!(to_server.unwrap()["error"]["code"], -32601, "{m} is refused to the server");
    }
    let logged = f.rec.0.lock().unwrap().iter().filter(|e| e.reason == Some(Reason::McpMethodNotAllowed)).count();
    assert_eq!(logged, 3);
}

fn arb_frame() -> impl Strategy<Value = Vec<u8>> {
    let method = prop_oneof![
        Just("tools/call"),
        Just("tools/list"),
        Just("initialize"),
        Just("resources/read"),
        Just("sampling/createMessage"),
        Just("notifications/cancelled"),
        Just("notifications/tools/list_changed"),
        Just("ping"),
    ];
    let tool = prop_oneof![Just("read"), Just("post"), Just("merge"), Just("nope"), Just("")];
    prop_oneof![
        (method, tool, any::<bool>(), 0i64..4).prop_map(|(m, t, with_id, id)| {
            let mut v = json!({"jsonrpc": "2.0", "method": m, "params": {"name": t, "arguments": {}}});
            if with_id {
                v["id"] = json!(id);
            }
            serde_json::to_vec(&v).unwrap()
        }),
        (0i64..4).prop_map(|id| serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": {}})).unwrap()),
        proptest::collection::vec(any::<u8>(), 0..64),
    ]
}

proptest! {
    /// Whatever the agent and the server send, only a tools/call of a
    /// pinned, permitted tool (or a cancellation) reaches the server, and
    /// no server request ever reaches the agent.
    #[test]
    fn only_permitted_calls_reach_the_server(
        steps in proptest::collection::vec((any::<bool>(), arb_frame()), 0..24),
        pinned in any::<bool>(),
    ) {
        let f = fx();
        let pin = if pinned { Pin::Pinned(manifest()) } else { Pin::Unapproved(manifest()) };
        let mut r = relay(&f, pin);
        for (from_agent, bytes) in steps {
            if from_agent {
                let (_, to_server) = r.on_agent(&bytes);
                if let Some(v) = to_server {
                    prop_assert!(pinned);
                    match v.get("method").and_then(|m| m.as_str()) {
                        Some("tools/call") => {
                            let t = v.pointer("/params/name").and_then(|n| n.as_str()).unwrap_or("");
                            prop_assert!(t == "read" || t == "post", "forwarded {t}");
                        }
                        Some("notifications/cancelled") => prop_assert!(v.get("id").is_none()),
                        other => prop_assert!(false, "forwarded {other:?}"),
                    }
                }
            } else {
                let (to_agent, _) = r.on_server(&bytes);
                if let Some(v) = to_agent {
                    let is_request = v.get("method").is_some() && v.get("id").is_some();
                    prop_assert!(!is_request, "a server request reached the agent");
                }
            }
        }
    }
}
