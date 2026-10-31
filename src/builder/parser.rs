use crate::health::HealthConfig;
use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    From {
        image: String,
        as_stage: Option<String>,
    },
    Run(String),
    Copy {
        from_stage: Option<String>,
        src: Vec<String>,
        dest: String,
    },
    Add {
        src: Vec<String>,
        dest: String,
    },
    Workdir(String),
    Env {
        key: String,
        value: String,
    },
    Cmd(Vec<String>),
    Entrypoint(Vec<String>),
    Expose(u16),
    ExposeRaw(String),
    Label {
        key: String,
        value: String,
    },
    Healthcheck(HealthConfig),
    Arg {
        name: String,
        default: Option<String>,
    },
    User(String),
    Volume(Vec<String>),
    StopSignal(String),
    Shell(Vec<String>),
    OnBuild(Box<Instruction>),
}

pub struct DockerfileParser;

impl DockerfileParser {
    pub fn parse_file(path: &Path) -> Result<Vec<Instruction>> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read Dockerfile at {:?}", path))?;
        Self::parse_str(&content)
    }

    pub fn parse_str(content: &str) -> Result<Vec<Instruction>> {
        let mut instructions = Vec::new();
        let mut current_line = String::new();

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(stripped) = line.strip_suffix('\\') {
                current_line.push_str(stripped.trim());
                current_line.push(' ');
                continue;
            } else {
                current_line.push_str(line);
            }

            let full_line = current_line.trim();
            if !full_line.is_empty() {
                let insts = Self::parse_line(full_line)?;
                instructions.extend(insts);
            }
            current_line.clear();
        }

        Ok(instructions)
    }

    fn parse_line(line: &str) -> Result<Vec<Instruction>> {
        let trimmed = line.trim();
        let (keyword, rest) = match trimmed.split_once(char::is_whitespace) {
            Some((k, r)) => (k.to_uppercase(), r.trim()),
            None => (trimmed.to_uppercase(), ""),
        };

        match keyword.as_str() {
            "FROM" => {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.is_empty() {
                    return Err(anyhow!("FROM instruction requires an image name"));
                }
                let image = parts[0].to_string();
                let as_stage = if parts.len() >= 3 && parts[1].eq_ignore_ascii_case("AS") {
                    Some(parts[2].to_string())
                } else {
                    None
                };
                Ok(vec![Instruction::From { image, as_stage }])
            }
            "RUN" => Ok(vec![Instruction::Run(rest.to_string())]),
            "COPY" => {
                let (from_stage, remainder) = if let Some(stripped) = rest.strip_prefix("--from=") {
                    let (stage, rem) = stripped
                        .split_once(char::is_whitespace)
                        .ok_or_else(|| anyhow!("Invalid COPY --from syntax"))?;
                    (Some(stage.to_string()), rem.trim())
                } else {
                    (None, rest)
                };

                let parts = parse_array_or_words(remainder);
                if parts.len() < 2 {
                    return Err(anyhow!(
                        "COPY requires at least one source and a destination"
                    ));
                }
                let dest = parts.last().unwrap().clone();
                let src = parts[..parts.len() - 1].to_vec();
                Ok(vec![Instruction::Copy {
                    from_stage,
                    src,
                    dest,
                }])
            }
            "ADD" => {
                let parts = parse_array_or_words(rest);
                if parts.len() < 2 {
                    return Err(anyhow!(
                        "ADD requires at least one source and a destination"
                    ));
                }
                let dest = parts.last().unwrap().clone();
                let src = parts[..parts.len() - 1].to_vec();
                Ok(vec![Instruction::Add { src, dest }])
            }
            "WORKDIR" => Ok(vec![Instruction::Workdir(rest.to_string())]),
            "ENV" => {
                let pairs = parse_key_value_pairs(rest);
                let mut insts = Vec::new();
                for (k, v) in pairs {
                    insts.push(Instruction::Env { key: k, value: v });
                }
                Ok(insts)
            }
            "ARG" => {
                if let Some((name, default)) = rest.split_once('=') {
                    Ok(vec![Instruction::Arg {
                        name: name.trim().to_string(),
                        default: Some(default.trim().to_string()),
                    }])
                } else {
                    Ok(vec![Instruction::Arg {
                        name: rest.trim().to_string(),
                        default: None,
                    }])
                }
            }
            "CMD" => {
                let cmd = parse_array_or_words(rest);
                Ok(vec![Instruction::Cmd(cmd)])
            }
            "ENTRYPOINT" => {
                let ep = parse_array_or_words(rest);
                Ok(vec![Instruction::Entrypoint(ep)])
            }
            "EXPOSE" => {
                let parts = parse_words(rest);
                if parts.is_empty() {
                    return Err(anyhow!("Invalid EXPOSE port"));
                }
                let mut insts = Vec::new();
                for raw in parts {
                    let (port_part, proto_part) = match raw.split_once('/') {
                        Some((p, proto)) => (p, Some(proto.to_lowercase())),
                        None => (raw.as_str(), None),
                    };
                    if proto_part.is_none() || proto_part.as_deref() == Some("tcp") {
                        if let Ok(port) = port_part.parse::<u16>() {
                            insts.push(Instruction::Expose(port));
                            continue;
                        }
                    }
                    let spec = match proto_part {
                        Some(proto) => format!("{}/{}", port_part, proto),
                        None => format!("{}/tcp", port_part),
                    };
                    insts.push(Instruction::ExposeRaw(spec));
                }
                Ok(insts)
            }
            "LABEL" => {
                let pairs = parse_key_value_pairs(rest);
                let mut insts = Vec::new();
                for (k, v) in pairs {
                    insts.push(Instruction::Label { key: k, value: v });
                }
                Ok(insts)
            }
            "HEALTHCHECK" => {
                let trimmed_rest = rest.trim();
                if trimmed_rest.eq_ignore_ascii_case("NONE") {
                    Ok(vec![Instruction::Healthcheck(HealthConfig {
                        test: Vec::new(),
                        ..Default::default()
                    })])
                } else {
                    let mut config = HealthConfig::default();
                    let mut current = trimmed_rest;
                    while current.starts_with("--") {
                        if let Some((flag, rem)) = current.split_once(char::is_whitespace) {
                            if let Some((name, val)) = flag.split_once('=') {
                                match name {
                                    "--interval" => {
                                        if let Ok(secs) = val.trim_end_matches('s').parse::<u64>() {
                                            config.interval_secs = secs;
                                        }
                                    }
                                    "--timeout" => {
                                        if let Ok(secs) = val.trim_end_matches('s').parse::<u64>() {
                                            config.timeout_secs = secs;
                                        }
                                    }
                                    "--start-period" => {
                                        if let Ok(secs) = val.trim_end_matches('s').parse::<u64>() {
                                            config.start_period_secs = secs;
                                        }
                                    }
                                    "--retries" => {
                                        if let Ok(r) = val.parse::<u32>() {
                                            config.retries = r;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            current = rem.trim();
                        } else {
                            break;
                        }
                    }

                    let cmd = if let Some(stripped) = current.strip_prefix("CMD ") {
                        parse_array_or_words(stripped.trim())
                    } else {
                        parse_array_or_words(current)
                    };
                    config.test = cmd;
                    Ok(vec![Instruction::Healthcheck(config)])
                }
            }
            "USER" => Ok(vec![Instruction::User(rest.to_string())]),
            "VOLUME" => {
                let vols = if rest.starts_with('[') && rest.ends_with(']') {
                    if let Ok(vec) = serde_json::from_str::<Vec<String>>(rest) {
                        vec
                    } else {
                        rest.split_whitespace()
                            .map(|w| {
                                let clean = w.trim_matches('"').replace('\'', "");
                                if clean.starts_with('/') {
                                    clean
                                } else {
                                    format!("/{}", clean)
                                }
                            })
                            .collect()
                    }
                } else {
                    parse_array_or_words(rest)
                };
                Ok(vec![Instruction::Volume(vols)])
            }
            "STOPSIGNAL" => Ok(vec![Instruction::StopSignal(rest.to_string())]),
            "SHELL" => {
                let shell = parse_array_or_words(rest);
                Ok(vec![Instruction::Shell(shell)])
            }
            "ONBUILD" => {
                let insts = Self::parse_line(rest)?;
                if insts.len() != 1 {
                    return Err(anyhow!("ONBUILD requires exactly one instruction"));
                }
                Ok(vec![Instruction::OnBuild(Box::new(insts[0].clone()))])
            }
            other => Err(anyhow!("Unsupported Dockerfile instruction: {}", other)),
        }
    }
}

pub fn parse_words(s: &str) -> Vec<String> {
    s.split_whitespace()
        .map(|w| w.trim_matches('"').to_string())
        .collect()
}

pub fn parse_array_or_words(s: &str) -> Vec<String> {
    if s.starts_with('[') && s.ends_with(']') {
        if let Ok(vec) = serde_json::from_str::<Vec<String>>(s) {
            return vec;
        }
    }
    parse_words(s)
}

pub fn parse_key_value_pairs(rest: &str) -> Vec<(String, String)> {
    let first_token = rest.split_whitespace().next().unwrap_or("");
    if !first_token.contains('=') {
        if let Some((k, v)) = rest.split_once(char::is_whitespace) {
            let key = k.trim().to_string();
            let val = v
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .replace("\\$", "$");
            return vec![(key, val)];
        }
        return Vec::new();
    }

    let mut pairs = Vec::new();
    let chars: Vec<char> = rest.chars().collect();
    let mut i = 0;
    let n = chars.len();

    while i < n {
        while i < n && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= n {
            break;
        }

        let mut key = String::new();
        while i < n && chars[i] != '=' && !chars[i].is_whitespace() {
            key.push(chars[i]);
            i += 1;
        }

        while i < n && chars[i].is_whitespace() {
            i += 1;
        }
        if i < n && chars[i] == '=' {
            i += 1;
        }

        while i < n && chars[i].is_whitespace() {
            i += 1;
        }

        let mut val = String::new();
        if i < n && (chars[i] == '"' || chars[i] == '\'') {
            let quote = chars[i];
            i += 1;
            while i < n && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < n {
                    i += 1;
                }
                val.push(chars[i]);
                i += 1;
            }
            if i < n && chars[i] == quote {
                i += 1;
            }
        } else {
            while i < n && !chars[i].is_whitespace() {
                val.push(chars[i]);
                i += 1;
            }
        }

        if !key.is_empty() {
            pairs.push((key, val));
        }
    }
    pairs
}
