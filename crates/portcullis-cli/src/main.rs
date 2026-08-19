//! The `portcullis` command.
//!
//! # Everything logs to stderr
//!
//! `run` speaks MCP on stdout. A single stray line there corrupts the framing
//! and the client sees a protocol error rather than a log message, so the
//! tracing subscriber is pinned to stderr and nothing else in this binary
//! writes to stdout while the gateway is serving.
//!
//! # The subcommands that do not run anything
//!
//! `validate`, `explain`, and `scan` all answer questions about configuration
//! without starting a server. That is deliberate: the alternative to
//! `portcullis explain` is discovering what a policy does by watching an agent
//! fail against it, which is a slow and expensive way to read a config file.

use clap::{Parser, Subcommand};
use portcullis_policy::{CallContext, Policy, TraceOutcome};
use portcullis_proxy::{Gateway, GatewayConfig};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// A policy-enforcing gateway for the Model Context Protocol.
#[derive(Debug, Parser)]
#[command(name = "portcullis", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the gateway, speaking MCP over stdio.
    Run {
        /// Gateway configuration.
        #[arg(short, long, default_value = "portcullis.toml")]
        config: PathBuf,
        /// Policy file.
        #[arg(short, long, default_value = "policies/default.toml")]
        policy: PathBuf,
    },

    /// Check a policy file and report anything suspicious.
    Validate {
        /// Policy file.
        #[arg(default_value = "policies/default.toml")]
        policy: PathBuf,
        /// Treat warnings as failures, for use in CI.
        #[arg(long)]
        strict: bool,
    },

    /// Show what a policy would decide for one call, and why.
    Explain {
        /// Policy file.
        #[arg(short, long, default_value = "policies/default.toml")]
        policy: PathBuf,
        /// The published tool name, for example `fs__read_file`.
        #[arg(short, long)]
        tool: String,
        /// The upstream that owns it. Defaults to the tool's namespace prefix.
        #[arg(short, long)]
        server: Option<String>,
        /// Call arguments as JSON.
        #[arg(short, long, default_value = "{}")]
        args: String,
    },

    /// Run the content scanners over a file or stdin.
    Scan {
        /// File to scan. Reads stdin when omitted.
        file: Option<PathBuf>,
    },

    /// List the upstreams a configuration declares.
    Servers {
        /// Gateway configuration.
        #[arg(short, long, default_value = "portcullis.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // stderr, always. stdout belongs to the protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PORTCULLIS_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let result = match cli.command {
        Command::Run { config, policy } => run(&config, &policy),
        Command::Validate { policy, strict } => validate(&policy, strict),
        Command::Explain {
            policy,
            tool,
            server,
            args,
        } => explain(&policy, &tool, server.as_deref(), &args),
        Command::Scan { file } => scan(file.as_deref()),
        Command::Servers { config } => servers(&config),
    };

    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("portcullis: {error}");
            let mut source = std::error::Error::source(&*error);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

type Fallible = Result<ExitCode, Box<dyn std::error::Error>>;

fn load_policy(path: &Path) -> Result<Policy, Box<dyn std::error::Error>> {
    let (policy, warnings) = portcullis_policy::load::from_path(path)?;
    for warning in warnings {
        eprintln!("{warning}");
    }
    Ok(policy)
}

fn load_config(path: &Path) -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(toml::from_str(&text)?)
}

#[tokio::main(flavor = "multi_thread")]
async fn run(config_path: &Path, policy_path: &Path) -> Fallible {
    let config = load_config(config_path)?;
    let policy = load_policy(policy_path)?;

    tracing::info!(
        servers = config.servers.len(),
        rules = policy.rules().len(),
        default = %policy.default_action(),
        "starting"
    );

    let gateway = Gateway::start(&config, policy).await?;
    tracing::info!(tools = gateway.registry().tools().len(), "ready");

    let result = gateway.serve(tokio::io::stdin(), tokio::io::stdout()).await;
    gateway.shutdown().await;
    result?;

    tracing::info!("client disconnected");
    Ok(ExitCode::SUCCESS)
}

fn validate(policy_path: &Path, strict: bool) -> Fallible {
    let (policy, warnings) = portcullis_policy::load::from_path(policy_path)?;

    for warning in &warnings {
        println!("{warning}");
    }

    println!(
        "{}: {} rules, default {}, {} warning(s)",
        policy_path.display(),
        policy.rules().len(),
        policy.default_action(),
        warnings.len()
    );

    if strict && !warnings.is_empty() {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn explain(policy_path: &Path, tool: &str, server: Option<&str>, args: &str) -> Fallible {
    let policy = load_policy(policy_path)?;
    let arguments: serde_json::Value =
        serde_json::from_str(args).map_err(|error| format!("--args is not valid JSON: {error}"))?;

    // A published name is `server__tool`, so the prefix is the upstream unless
    // the caller says otherwise.
    let inferred = tool.split("__").next().unwrap_or(tool);
    let server = server.unwrap_or(inferred);

    let explained = policy.explain(&CallContext::new(server, tool, Some(&arguments)));

    println!("call    {server} / {tool}");
    println!("args    {arguments}");
    println!();

    for entry in &explained.trace {
        let marker = match &entry.outcome {
            TraceOutcome::Applied => "->",
            TraceOutcome::NotReached => "  ",
            _ => " .",
        };
        let detail = match &entry.outcome {
            TraceOutcome::Applied => "applied".to_owned(),
            TraceOutcome::ServerMismatch => "skipped: restricted to other servers".to_owned(),
            TraceOutcome::ToolMismatch => "skipped: tool patterns do not match".to_owned(),
            TraceOutcome::ConditionUnmet { condition } => {
                format!("skipped: condition not met ({condition})")
            }
            TraceOutcome::NotReached => "not reached".to_owned(),
        };
        println!(
            "{marker} [{:>2}] {:<32} {:<5} {detail}",
            entry.index, entry.id, entry.action
        );
    }

    println!();
    println!("decision {}", explained.decision.reason());

    // Exit code mirrors the decision so this composes in a shell.
    Ok(if explained.decision.is_allowed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn scan(file: Option<&Path>) -> Fallible {
    let text = match file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?,
        None => std::io::read_to_string(std::io::stdin())?,
    };

    let unicode = portcullis_scan::unicode::scan(&text);
    let hidden = portcullis_scan::unicode::hidden_text(&unicode);
    let mut injection = portcullis_scan::injection::scan(&text);
    if !hidden.is_empty() {
        injection.extend(portcullis_scan::injection::scan(&hidden));
    }
    let secrets = portcullis_scan::secret::scan(&text);

    for finding in &unicode {
        print!(
            "unicode   {:<20} {} char(s)",
            finding.category.label(),
            finding.count
        );
        match &finding.decoded {
            Some(text) if !text.is_empty() => println!("  hidden: {text:?}"),
            _ => println!(),
        }
    }
    for finding in &injection {
        println!(
            "injection {:<20} {:<8} {:?}",
            finding.kind.label(),
            finding.severity,
            finding.excerpt
        );
    }
    for finding in &secrets {
        println!(
            "secret    {:<20} {}",
            finding.kind.label(),
            finding.marker()
        );
    }

    let total = unicode.len() + injection.len() + secrets.len();
    println!("{total} finding(s)");

    Ok(if total == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn servers(config_path: &Path) -> Fallible {
    let config = load_config(config_path)?;
    for server in &config.servers {
        println!(
            "{:<16} {} {}",
            server.name,
            server.command,
            server.args.join(" ")
        );
    }
    println!("{} server(s)", config.servers.len());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_subcommand_parses() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["portcullis", "run"],
            vec!["portcullis", "validate", "--strict"],
            vec!["portcullis", "explain", "--tool", "fs__read_file"],
            vec!["portcullis", "scan"],
            vec!["portcullis", "servers"],
        ];
        for argv in cases {
            Cli::try_parse_from(&argv).unwrap_or_else(|error| panic!("{argv:?}: {error}"));
        }
    }

    #[test]
    fn the_upstream_is_inferred_from_the_namespace_prefix() {
        // The behaviour that lets `explain --tool fs__read_file` work without
        // also making the caller repeat the server name.
        assert_eq!("fs__read_file".split("__").next(), Some("fs"));
        assert_eq!("unnamespaced".split("__").next(), Some("unnamespaced"));
    }
}
