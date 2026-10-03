use agentfence::event::read_jsonl;
use agentfence::profile::{tilde, Profile};
use agentfence::report::{self, Source};
use agentfence::roles::ProtectOpts;
use agentfence::store::{Meta, Store};
use agentfence::synth::cover::{CostModel, RealFs};
use agentfence::synth::{synthesize, SynthOptions, TraceInput};
use agentfence::{learn, rules, run};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::PathBuf;

/// Learn-mode least-privilege sandboxing for AI coding agents.
#[derive(Parser)]
#[command(name = "agentfence", version, about)]
struct Cli {
    /// Project directory (holds `.agentfence/`). Defaults to the current directory.
    #[arg(long, global = true, default_value = ".")]
    project: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command under strace and record what it touches.
    Learn {
        /// Label appended to the trace file name (e.g. the task).
        #[arg(long)]
        name: Option<String>,
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Turn recorded traces into a Landlock profile.
    Synth {
        /// Count real files for the privilege cost (default) or use a depth heuristic only.
        #[arg(long)]
        no_fs_estimate: bool,
        /// Price of one rule relative to one reachable file (higher = fewer, broader rules).
        #[arg(long, default_value_t = 320)]
        rule_overhead: u64,
        /// Do not protect .git/hooks and .git/config (lets `git commit` work).
        #[arg(long)]
        allow_git_writes: bool,
        /// Extra project path that must never be writable (repeatable).
        #[arg(long = "protect")]
        protect: Vec<PathBuf>,
        /// Release a path from the built-in secret list, e.g. the agent's own
        /// credentials (repeatable; use sparingly).
        #[arg(long = "allow-secret")]
        allow_secret: Vec<PathBuf>,
        /// Only grant what was observed; skip the whole-project read/write grant.
        #[arg(long)]
        no_project_grant: bool,
        /// Only grant observed system paths; skip read+exec on /usr, /lib*, /bin,
        /// /sbin, /opt and read on /etc (tighter, but unseen tools get denied).
        #[arg(long)]
        no_system_grant: bool,
        /// Output profile path (default: .agentfence/profile.toml).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run a command with the profile enforced (unprivileged, via Landlock).
    Run {
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Do not wrap in strace / do not record denials.
        #[arg(long)]
        no_record: bool,
        /// Continue even if the kernel enforces nothing (NOT recommended).
        #[arg(long)]
        allow_unenforced: bool,
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show what the profile blocked (or would block) and what is new.
    Report {
        /// Denial log to explain (default: newest in .agentfence/denials/).
        #[arg(long, conflicts_with = "trace")]
        denials: Option<PathBuf>,
        /// Compare a (new) learn trace against the profile instead.
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Color::Auto)]
        color: Color,
    },
    /// Check strace / Landlock availability on this machine.
    Doctor,
}

#[derive(Clone, Copy, ValueEnum)]
enum Color {
    Auto,
    Always,
    Never,
}

fn main() {
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("agentfence: error: {e:#}");
            std::process::exit(1);
        }
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Doctor => {
            print!("{}", run::doctor());
            Ok(0)
        }
        Cmd::Learn { name, command } => {
            let store = Store::new(&cli.project)?;
            learn::learn(&store, &command, name.as_deref())
        }
        Cmd::Synth {
            no_fs_estimate,
            rule_overhead,
            allow_git_writes,
            protect,
            allow_secret,
            no_project_grant,
            no_system_grant,
            out,
        } => {
            let store = Store::new(&cli.project)?;
            synth_cmd(
                &store,
                no_fs_estimate,
                rule_overhead,
                allow_git_writes,
                protect,
                allow_secret,
                no_project_grant,
                no_system_grant,
                out,
            )?;
            Ok(0)
        }
        Cmd::Run {
            profile,
            no_record,
            allow_unenforced,
            command,
        } => {
            let store = Store::new(&cli.project)?;
            let path = profile.unwrap_or_else(|| store.profile_path());
            if !path.exists() {
                bail!(
                    "no profile at {} (run `agentfence synth` first)",
                    path.display()
                );
            }
            if no_record {
                let prof = Profile::load(&path)?;
                run::restrict_and_exec(&prof, &command, allow_unenforced, false)?;
                unreachable!("exec returned");
            }
            run::run_recorded(&store, &path, &command, allow_unenforced)
        }
        Cmd::Report {
            denials,
            trace,
            profile,
            color,
        } => {
            let store = Store::new(&cli.project)?;
            let ppath = profile.unwrap_or_else(|| store.profile_path());
            let prof = Profile::load(&ppath)?;
            let (source, path) = match (denials, trace) {
                (_, Some(t)) => {
                    let t = if t.exists() {
                        t
                    } else {
                        store.traces_dir().join(format!("{}.jsonl", t.display()))
                    };
                    (Source::Trace, t)
                }
                (Some(d), None) => (Source::Denials, d),
                (None, None) => match store.latest_denials() {
                    Some(d) => (Source::Denials, d),
                    None => bail!(
                        "no denial logs in {} (use `agentfence run`, or --trace FILE)",
                        store.denials_dir().display()
                    ),
                },
            };
            let events = run::load_events(&path)?;
            let rep = report::build(&prof, &events, source);
            let use_color = match color {
                Color::Always => true,
                Color::Never => false,
                Color::Auto => {
                    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
                }
            };
            print!(
                "{}",
                report::render(&prof, &rep, source, &path.display().to_string(), use_color)
            );
            Ok(0)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn synth_cmd(
    store: &Store,
    no_fs_estimate: bool,
    rule_overhead: u64,
    allow_git_writes: bool,
    protect: Vec<PathBuf>,
    allow_secret: Vec<PathBuf>,
    no_project_grant: bool,
    no_system_grant: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    let stems = store.trace_stems();
    if stems.is_empty() {
        bail!(
            "no traces in {} (run `agentfence learn -- <command>` first)",
            store.traces_dir().display()
        );
    }
    let mut inputs = Vec::new();
    let mut last_meta: Option<Meta> = None;
    for s in &stems {
        let events = read_jsonl(&std::fs::read_to_string(
            store.traces_dir().join(format!("{s}.jsonl")),
        )?)
        .with_context(|| format!("trace {s}"))?;
        if let Ok(m) = std::fs::read_to_string(store.traces_dir().join(format!("{s}.meta.json"))) {
            last_meta = serde_json::from_str(&m).ok();
        }
        inputs.push(TraceInput {
            name: s.clone(),
            events,
        });
    }
    let home = last_meta
        .as_ref()
        .map(|m| m.home.clone())
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("HOME").ok())
        .context("cannot determine the HOME the agent ran with")?;
    let opts = SynthOptions {
        project: store.project.clone(),
        home: PathBuf::from(home),
        tmpdir: last_meta
            .as_ref()
            .and_then(|m| m.tmpdir.clone())
            .map(PathBuf::from),
        protect: ProtectOpts {
            allow_git_writes,
            extra_protected: protect,
            allow_secrets: allow_secret,
        },
        cost: CostModel {
            rule_overhead,
            ..CostModel::default()
        },
        project_grant: !no_project_grant,
        system_grant: !no_system_grant,
    };
    let fs = RealFs::new(!no_fs_estimate);
    let profile = synthesize(&inputs, &opts, &fs);

    store.ensure(&store.root)?;
    let out = out.unwrap_or_else(|| store.profile_path());
    let rules_text = rules::compile(&profile, &|p| p.is_dir())?;
    profile.save(&out)?;
    let rules_path = out.with_extension("rules");
    std::fs::write(&rules_path, rules_text)?;

    let home_s = &profile.home;
    eprintln!(
        "agentfence: synthesized {} rule(s) from {} trace(s) -> {} (+ {})",
        profile.rules.len(),
        stems.len(),
        out.display(),
        rules_path.display()
    );
    eprintln!(
        "  network: TCP connect ports {:?}, bind ports {:?}",
        profile.network.connect_tcp, profile.network.bind_tcp
    );
    if !profile.blocked_secrets.is_empty() {
        eprintln!("  WARNING: the agent touched secrets during learning; they are NOT granted:");
        for s in &profile.blocked_secrets {
            eprintln!("    - {s}");
        }
    }
    if !profile.unmet.is_empty() {
        eprintln!("  not granted (would expose protected paths):");
        for u in profile.unmet.iter().take(20) {
            eprintln!("    - {u}");
        }
        if profile.unmet.len() > 20 {
            eprintln!(
                "    ... and {} more (see profile.toml)",
                profile.unmet.len() - 20
            );
        }
    }
    for w in &profile.warnings {
        eprintln!("  note: {}", tilde(w, home_s));
    }
    Ok(())
}
