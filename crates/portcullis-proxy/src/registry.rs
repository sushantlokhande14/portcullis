//! Presenting several upstream servers as one.
//!
//! The client sees a single flat tool list. Each entry carries a namespaced
//! name, and the registry remembers which upstream owns it and what that
//! upstream calls it, so a `tools/call` can be routed and un-namespaced on the
//! way through.
//!
//! # Why `__` and not `.`
//!
//! A dot reads better, and it is what the policy examples in early drafts used.
//! It is also unsafe: several MCP clients validate tool names against
//! `^[a-zA-Z0-9_-]{1,64}$` and will drop or reject a name containing a dot. A
//! gateway whose tools silently fail to appear in half the clients that connect
//! to it is not much of a gateway, so the default separator is `__`, which is
//! what other aggregators settled on for the same reason. It stays configurable
//! for anyone whose client is stricter still.
//!
//! # Pagination is resolved here
//!
//! `tools/list` is paginated upstream. The registry walks every page at refresh
//! time and hands the client one complete list with no cursor. It has to: a
//! cursor is opaque and server-specific, so a merged cursor spanning several
//! upstreams would have to be invented and tracked, and every name has to be
//! rewritten before the client sees it anyway. Materialising is the honest
//! version of what a namespacing proxy already does.

use crate::upstream::{Upstream, UpstreamError};
use portcullis_core::mcp::{ListToolsParams, ListToolsResult};
use portcullis_core::{Tool, method};
use std::collections::HashMap;

/// The default namespace separator.
pub const DEFAULT_SEPARATOR: &str = "__";

/// Longest namespaced tool name the registry will publish.
///
/// Clients differ on the limit; 64 is the strictest seen in the wild and 128 is
/// the most permissive. Names longer than this are dropped with a warning
/// rather than truncated, because two truncated names can collide and routing
/// the wrong call to the wrong tool is worse than not offering it.
pub const MAX_TOOL_NAME_LEN: usize = 128;

/// How to reach the tool behind a published name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The upstream that owns it.
    pub server: String,
    /// What that upstream calls it, without the namespace prefix.
    pub upstream_name: String,
}

/// A tool that could not be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedTool {
    /// The upstream that offered it.
    pub server: String,
    /// The name it offered.
    pub name: String,
    /// Why it was not published.
    pub reason: String,
}

/// The merged view of every upstream's tools.
#[derive(Debug, Default, Clone)]
pub struct ToolRegistry {
    separator: String,
    tools: Vec<Tool>,
    routes: HashMap<String, Route>,
    skipped: Vec<SkippedTool>,
}

impl ToolRegistry {
    /// An empty registry using the default separator.
    pub fn new() -> Self {
        Self {
            separator: DEFAULT_SEPARATOR.to_owned(),
            tools: Vec::new(),
            routes: HashMap::new(),
            skipped: Vec::new(),
        }
    }

    /// Uses a different namespace separator.
    #[must_use]
    pub fn with_separator(mut self, separator: impl Into<String>) -> Self {
        self.separator = separator.into();
        self
    }

    /// The published name for an upstream's tool.
    pub fn namespaced(&self, server: &str, tool: &str) -> String {
        format!("{server}{}{tool}", self.separator)
    }

    /// The tools to advertise to the client.
    pub fn tools(&self) -> &[Tool] {
        &self.tools
    }

    /// Tools that were offered but not published.
    pub fn skipped(&self) -> &[SkippedTool] {
        &self.skipped
    }

    /// Where a published name routes to.
    pub fn route(&self, published_name: &str) -> Option<&Route> {
        self.routes.get(published_name)
    }

    /// Adds one upstream's tools, rewriting their names.
    ///
    /// Returns the number published. A name that collides with one already
    /// registered is skipped rather than replacing it: registration order is
    /// configuration order, so the first upstream listed wins, which is at
    /// least a rule an operator can predict and reorder.
    pub fn register(&mut self, server: &str, tools: Vec<Tool>) -> usize {
        let mut published = 0;

        for mut tool in tools {
            let upstream_name = tool.name.clone();
            let published_name = self.namespaced(server, &upstream_name);

            if published_name.len() > MAX_TOOL_NAME_LEN {
                self.skipped.push(SkippedTool {
                    server: server.to_owned(),
                    name: upstream_name,
                    reason: format!(
                        "namespaced name is {} characters, over the {MAX_TOOL_NAME_LEN} limit",
                        published_name.len()
                    ),
                });
                continue;
            }

            if let Some(existing) = self.routes.get(&published_name) {
                self.skipped.push(SkippedTool {
                    server: server.to_owned(),
                    name: upstream_name,
                    reason: format!(
                        "name {published_name:?} is already served by upstream {:?}",
                        existing.server
                    ),
                });
                continue;
            }

            tool.name.clone_from(&published_name);
            self.routes.insert(
                published_name,
                Route {
                    server: server.to_owned(),
                    upstream_name,
                },
            );
            self.tools.push(tool);
            published += 1;
        }

        published
    }

    /// Fetches every page of an upstream's tool list and registers it.
    pub async fn register_from(&mut self, upstream: &Upstream) -> Result<usize, UpstreamError> {
        let mut cursor: Option<String> = None;
        let mut collected = Vec::new();

        loop {
            let params = ListToolsParams {
                cursor: cursor.take(),
                ..Default::default()
            };
            let raw = upstream
                .request(
                    method::TOOLS_LIST,
                    Some(serde_json::to_value(params).expect("list params serialise")),
                )
                .await?;

            let page: ListToolsResult =
                serde_json::from_value(raw).map_err(|error| UpstreamError::Malformed {
                    name: upstream.name().to_owned(),
                    method: method::TOOLS_LIST.to_owned(),
                    detail: error.to_string(),
                })?;

            collected.extend(page.tools);

            match page.next_cursor {
                // A server that keeps handing back a cursor forever would loop
                // here indefinitely, so an empty page ends the walk regardless.
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => break,
            }
        }

        Ok(self.register(upstream.name(), collected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::Tool;

    fn tools(names: &[&str]) -> Vec<Tool> {
        names.iter().map(|name| Tool::new(*name)).collect()
    }

    #[test]
    fn publishes_namespaced_names_and_routes_them_back() {
        let mut registry = ToolRegistry::new();
        assert_eq!(
            registry.register("fs", tools(&["read_file", "write_file"])),
            2
        );

        assert_eq!(
            registry
                .tools()
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            vec!["fs__read_file", "fs__write_file"]
        );

        let route = registry.route("fs__read_file").expect("routed");
        assert_eq!(route.server, "fs");
        assert_eq!(
            route.upstream_name, "read_file",
            "the upstream sees its own name"
        );
        assert!(
            registry.route("read_file").is_none(),
            "unqualified names are not published"
        );
    }

    #[test]
    fn the_default_separator_keeps_names_client_safe() {
        // A dot reads better but several clients validate against
        // ^[a-zA-Z0-9_-]{1,64}$ and drop anything else.
        let registry = ToolRegistry::new();
        let name = registry.namespaced("github", "create_issue");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "{name} is not client-safe"
        );
    }

    #[test]
    fn identical_tool_names_on_different_servers_do_not_collide() {
        // The whole point of namespacing: two servers with a `search` tool.
        let mut registry = ToolRegistry::new();
        registry.register("github", tools(&["search"]));
        registry.register("slack", tools(&["search"]));

        assert_eq!(registry.tools().len(), 2);
        assert_eq!(registry.route("github__search").unwrap().server, "github");
        assert_eq!(registry.route("slack__search").unwrap().server, "slack");
        assert!(registry.skipped().is_empty());
    }

    #[test]
    fn a_genuine_collision_keeps_the_first_and_records_the_second() {
        let mut registry = ToolRegistry::new();
        registry.register("fs", tools(&["read"]));
        assert_eq!(registry.register("fs", tools(&["read"])), 0);

        assert_eq!(registry.tools().len(), 1);
        assert_eq!(registry.skipped().len(), 1);
        assert!(
            registry.skipped()[0].reason.contains("already served"),
            "{:?}",
            registry.skipped()
        );
    }

    #[test]
    fn an_over_long_name_is_dropped_rather_than_truncated() {
        // Truncating can make two distinct tools share a name, and routing a
        // call to the wrong tool is worse than not offering it at all.
        let mut registry = ToolRegistry::new();
        let long = "x".repeat(MAX_TOOL_NAME_LEN);
        assert_eq!(registry.register("srv", tools(&[long.as_str()])), 0);

        assert!(registry.tools().is_empty());
        assert!(
            registry.skipped()[0].reason.contains("over the"),
            "{:?}",
            registry.skipped()
        );
    }

    #[test]
    fn a_custom_separator_is_honoured_everywhere() {
        let mut registry = ToolRegistry::new().with_separator(".");
        registry.register("fs", tools(&["read"]));
        assert_eq!(registry.tools()[0].name, "fs.read");
        assert!(registry.route("fs.read").is_some());
    }

    #[test]
    fn registration_preserves_everything_but_the_name() {
        let mut tool = Tool::new("read");
        tool.description = Some("Reads a file".to_owned());
        tool.annotations = Some(portcullis_core::ToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        });

        let mut registry = ToolRegistry::new();
        registry.register("fs", vec![tool]);

        let published = &registry.tools()[0];
        assert_eq!(published.name, "fs__read");
        assert_eq!(published.description.as_deref(), Some("Reads a file"));
        assert!(published.annotations.as_ref().unwrap().asserts_read_only());
    }
}
