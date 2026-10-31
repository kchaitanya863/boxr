use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String, // "container", "image", "volume", "network", "pod", "system"
    pub action: String,     // "create", "start", "died", "stop", "remove", etc.
    pub actor_id: String,
    pub actor_name: String,
    pub attributes: HashMap<String, String>,
}

impl ContainerEvent {
    pub fn new(
        event_type: &str,
        action: &str,
        actor_id: &str,
        actor_name: &str,
        attributes: HashMap<String, String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            action: action.to_string(),
            actor_id: actor_id.to_string(),
            actor_name: actor_name.to_string(),
            attributes,
        }
    }

    pub fn display_line(&self) -> String {
        self.display_line_with_trunc(false)
    }

    pub fn display_line_with_trunc(&self, no_trunc: bool) -> String {
        let ts = self.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, false);
        match self.event_type.as_str() {
            "image" => {
                if self.action == "pull-error" {
                    let err_msg = self.attributes.get("error").cloned().unwrap_or_default();
                    return format!("{} image pull-error  {} {}", ts, self.actor_name, err_msg);
                }
                return format!(
                    "{} image {} {} {}",
                    ts, self.action, self.actor_id, self.actor_name
                );
            }
            "volume" | "pod" => {
                return format!(
                    "{} {} {} {}",
                    ts, self.event_type, self.action, self.actor_name
                );
            }
            "network" => {
                let mut attrs_str = Vec::new();
                if let Some(n) = self.attributes.get("name") {
                    attrs_str.push(format!("name={}", n));
                }
                if let Some(t) = self.attributes.get("type") {
                    attrs_str.push(format!("type={}", t));
                }
                for (k, v) in &self.attributes {
                    if k != "name" && k != "type" {
                        attrs_str.push(format!("{}={}", k, v));
                    }
                }
                let attrs_formatted = if attrs_str.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", attrs_str.join(", "))
                };
                return format!(
                    "{} network {} {}{}",
                    ts, self.action, self.actor_id, attrs_formatted
                );
            }
            "system" => {
                return format!("{} system {} {}", ts, self.action, self.actor_name);
            }
            _ => {}
        }

        let mut attrs_str = Vec::new();
        if let Some(img) = self.attributes.get("image") {
            attrs_str.push(format!("image={}", img));
        }
        if let Some(name) = self.attributes.get("name") {
            attrs_str.push(format!("name={}", name));
        }
        let mut extra_keys: Vec<&String> = self
            .attributes
            .keys()
            .filter(|k| {
                k.as_str() != "image"
                    && k.as_str() != "name"
                    && k.as_str() != "containerInspectData"
            })
            .collect();
        extra_keys.sort();
        for k in extra_keys {
            if let Some(v) = self.attributes.get(k) {
                attrs_str.push(format!("{}={}", k, v));
            }
        }
        attrs_str.sort();
        let attrs_formatted = if attrs_str.is_empty() {
            "".to_string()
        } else {
            format!(" ({})", attrs_str.join(", "))
        };

        let id_str = if no_trunc || self.event_type == "network" || self.event_type == "secret" {
            self.actor_id.as_str()
        } else {
            &self.actor_id[..12.min(self.actor_id.len())]
        };

        format!(
            "{} {} {} {}{}",
            ts, self.event_type, self.action, id_str, attrs_formatted
        )
    }

    pub fn to_podman_file_json(&self) -> String {
        let time_str = self.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, false);
        let attrs_val = if self.attributes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::to_value(&self.attributes).unwrap_or(serde_json::Value::Null)
        };
        if self.event_type == "container" {
            let img = self.attributes.get("image").cloned().unwrap_or_default();
            let obj = serde_json::json!({
                "ID": self.actor_id,
                "Image": img,
                "Name": self.actor_name,
                "Status": self.action,
                "Time": time_str,
                "Type": self.event_type,
                "Attributes": attrs_val,
                "timestamp": self.timestamp,
                "event_type": self.event_type,
                "action": self.action,
                "actor_id": self.actor_id,
                "actor_name": self.actor_name,
                "attributes": self.attributes,
            });
            serde_json::to_string(&obj).unwrap_or_default()
        } else {
            let obj = serde_json::json!({
                "Name": self.actor_name,
                "Status": self.action,
                "Time": time_str,
                "Type": self.event_type,
                "Attributes": attrs_val,
                "ID": self.actor_id,
                "timestamp": self.timestamp,
                "event_type": self.event_type,
                "action": self.action,
                "actor_id": self.actor_id,
                "actor_name": self.actor_name,
                "attributes": self.attributes,
            });
            serde_json::to_string(&obj).unwrap_or_default()
        }
    }

    pub fn to_podman_stream_json(&self) -> String {
        let secs = self.timestamp.timestamp();
        let nanos = self
            .timestamp
            .timestamp_nanos_opt()
            .unwrap_or(secs * 1_000_000_000);
        let attrs_val = if self.attributes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::to_value(&self.attributes).unwrap_or(serde_json::Value::Null)
        };
        if self.event_type == "container" {
            let img = self.attributes.get("image").cloned().unwrap_or_default();
            format!(
                "{{\"ID\":{},\"Image\":{},\"Name\":{},\"Status\":{},\"time\":{},\"timeNano\":{},\"Type\":{},\"Attributes\":{}}}",
                serde_json::to_string(&self.actor_id).unwrap_or_default(),
                serde_json::to_string(&img).unwrap_or_default(),
                serde_json::to_string(&self.actor_name).unwrap_or_default(),
                serde_json::to_string(&self.action).unwrap_or_default(),
                secs,
                nanos,
                serde_json::to_string(&self.event_type).unwrap_or_default(),
                serde_json::to_string(&attrs_val).unwrap_or_else(|_| "null".to_string()),
            )
        } else {
            format!(
                "{{\"Name\":{},\"Status\":{},\"time\":{},\"timeNano\":{},\"Type\":{},\"Attributes\":{}}}",
                serde_json::to_string(&self.actor_name).unwrap_or_default(),
                serde_json::to_string(&self.action).unwrap_or_default(),
                secs,
                nanos,
                serde_json::to_string(&self.event_type).unwrap_or_default(),
                serde_json::to_string(&attrs_val).unwrap_or_else(|_| "null".to_string()),
            )
        }
    }
}

/// Open/Closed & Interface Segregation: Event emission abstraction
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &ContainerEvent) -> Result<()>;
}

/// Open/Closed: Event filtering abstraction
pub trait EventFilter: Send + Sync {
    fn matches(&self, event: &ContainerEvent) -> bool;
}

/// JSONL file sink implementation of EventSink
pub struct JsonlFileSink {
    path: PathBuf,
}

impl JsonlFileSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl EventSink for JsonlFileSink {
    fn emit(&self, event: &ContainerEvent) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = event.to_podman_file_json();
        writeln!(file, "{}", line)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct EventsConf {
    logger: Option<String>,
    logfile_path: Option<PathBuf>,
    max_size: Option<u64>,
    container_create_inspect_data: bool,
}

fn load_events_conf() -> EventsConf {
    let mut conf = EventsConf::default();
    let mut files = Vec::new();
    if let Ok(p) = std::env::var("CONTAINERS_CONF") {
        if !p.is_empty() {
            files.push(PathBuf::from(p));
        }
    }
    if let Ok(p) = std::env::var("CONTAINERS_CONF_OVERRIDE") {
        if !p.is_empty() {
            files.push(PathBuf::from(p));
        }
    }
    for path in files {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let k = k.trim();
            let v = v.trim().trim_matches('"').trim_matches('\'');
            match k {
                "events_logger" => conf.logger = Some(v.to_string()),
                "events_logfile_path" => conf.logfile_path = Some(PathBuf::from(v)),
                "events_logfile_max_size" => {
                    conf.max_size = v.parse::<u64>().ok();
                }
                "events_container_create_inspect_data" => {
                    conf.container_create_inspect_data = v.eq_ignore_ascii_case("true") || v == "1";
                }
                _ => {}
            }
        }
    }
    if let Some(cli_backend) = crate::cli::podman_globals::podman_global_options().events_backend {
        conf.logger = Some(cli_backend);
    }
    conf
}

fn parse_event_line(trimmed: &str) -> Option<ContainerEvent> {
    if let Ok(ev) = serde_json::from_str::<ContainerEvent>(trimmed) {
        return Some(ev);
    }
    let val: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let event_type = val.get("Type")?.as_str()?.to_string();
    let action = val.get("Status")?.as_str()?.to_string();
    let actor_name = val
        .get("Name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let actor_id = val
        .get("ID")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let time_str = val.get("Time")?.as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(time_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let mut attributes: HashMap<String, String> = val
        .get("Attributes")
        .and_then(|a| serde_json::from_value(a.clone()).ok())
        .unwrap_or_default();
    if let Some(img) = val.get("Image").and_then(|v| v.as_str()) {
        if !img.is_empty() {
            attributes
                .entry("image".to_string())
                .or_insert_with(|| img.to_string());
        }
    }
    if !actor_name.is_empty() && event_type == "container" {
        attributes
            .entry("name".to_string())
            .or_insert_with(|| actor_name.clone());
    }
    Some(ContainerEvent {
        timestamp,
        event_type,
        action,
        actor_id,
        actor_name,
        attributes,
    })
}

fn rotate_podman_events_file_if_needed(path: &Path, max_size: u64) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.len() < max_size {
        return;
    }
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let start_idx = (lines.len() / 2 + 1).min(lines.len());
    let kept = &lines[start_idx..];
    let path_str = path.to_string_lossy().to_string();
    let now_begin = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, false);
    let begin_line = format!(
        "{{\"Name\":{},\"Status\":\"log-rotation\",\"Time\":{},\"Type\":\"system\",\"Attributes\":{{\"io.podman.event.rotate\":\"begin\"}}}}",
        serde_json::to_string(&path_str).unwrap_or_default(),
        serde_json::to_string(&now_begin).unwrap_or_default(),
    );
    let now_end = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, false);
    let end_line = format!(
        "{{\"Name\":{},\"Status\":\"log-rotation\",\"Time\":{},\"Type\":\"system\",\"Attributes\":{{\"io.podman.event.rotate\":\"end\"}}}}",
        serde_json::to_string(&path_str).unwrap_or_default(),
        serde_json::to_string(&now_end).unwrap_or_default(),
    );
    let mut new_content = String::new();
    new_content.push_str(&begin_line);
    new_content.push('\n');
    for l in kept {
        new_content.push_str(l);
        new_content.push('\n');
    }
    new_content.push_str(&end_line);
    new_content.push('\n');
    let _ = fs::write(path, new_content);
}

fn append_podman_strict_event_line(path: &Path, event: &ContainerEvent) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let time_str = event.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, false);
    let attrs_val = if event.attributes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::to_value(&event.attributes).unwrap_or(serde_json::Value::Null)
    };
    let line = if event.event_type == "container" {
        let img = event.attributes.get("image").cloned().unwrap_or_default();
        format!(
            "{{\"ID\":{},\"Image\":{},\"Name\":{},\"Status\":{},\"Time\":{},\"Type\":\"container\",\"Attributes\":{}}}",
            serde_json::to_string(&event.actor_id).unwrap_or_default(),
            serde_json::to_string(&img).unwrap_or_default(),
            serde_json::to_string(&event.actor_name).unwrap_or_default(),
            serde_json::to_string(&event.action).unwrap_or_default(),
            serde_json::to_string(&time_str).unwrap_or_default(),
            serde_json::to_string(&attrs_val).unwrap_or_else(|_| "null".to_string()),
        )
    } else {
        format!(
            "{{\"Name\":{},\"Status\":{},\"Time\":{},\"Type\":{},\"Attributes\":{}}}",
            serde_json::to_string(&event.actor_name).unwrap_or_default(),
            serde_json::to_string(&event.action).unwrap_or_default(),
            serde_json::to_string(&time_str).unwrap_or_default(),
            serde_json::to_string(&event.event_type).unwrap_or_default(),
            serde_json::to_string(&attrs_val).unwrap_or_else(|_| "null".to_string()),
        )
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{}", line);
    }
}

pub fn parse_event_timestamp(input: &str) -> Result<DateTime<Utc>> {
    let s = input.trim();
    if s.is_empty() {
        return Err(anyhow!("failed to parse event filters: empty timestamp"));
    }
    let normalized = s.replace(',', ".");
    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Some(num) = s.strip_suffix('s') {
        if let Ok(secs) = num.parse::<i64>() {
            return Ok(Utc::now() - ChronoDuration::seconds(secs));
        }
    }
    if let Some(num) = s.strip_suffix('m') {
        if let Ok(mins) = num.parse::<i64>() {
            return Ok(Utc::now() - ChronoDuration::minutes(mins));
        }
    }
    if let Some(num) = s.strip_suffix('h') {
        if let Ok(hours) = num.parse::<i64>() {
            return Ok(Utc::now() - ChronoDuration::hours(hours));
        }
    }
    if let Ok(unix_secs) = s.parse::<i64>() {
        if let Some(dt) = DateTime::<Utc>::from_timestamp(unix_secs, 0) {
            return Ok(dt);
        }
    }
    Err(anyhow!(
        "failed to parse event filters: cannot parse \"{}\" as timestamp",
        input
    ))
}

fn match_single_filter_kv(event: &ContainerEvent, k: &str, v: &str) -> bool {
    match k {
        "event" | "action" | "status" => {
            if event.action == v {
                return true;
            }
            if (v == "die" || v == "died") && (event.action == "die" || event.action == "died") {
                return true;
            }
            if (v == "destroy" || v == "remove")
                && (event.action == "destroy" || event.action == "remove")
            {
                return true;
            }
            false
        }
        "type" => event.event_type == v,
        "container" => {
            event.event_type == "container"
                && (event.actor_name == v
                    || (!v.is_empty() && event.actor_id.starts_with(v))
                    || event.attributes.get("name").is_some_and(|n| n == v))
        }
        "image" => {
            event.actor_name == v
                || (!v.is_empty() && event.actor_id.starts_with(v))
                || event.attributes.get("image").is_some_and(|i| i == v)
        }
        "volume" => {
            event.event_type == "volume"
                && (event.actor_name == v || (!v.is_empty() && event.actor_name.starts_with(v)))
        }
        "pod" => {
            event.event_type == "pod"
                && (event.actor_name == v || (!v.is_empty() && event.actor_id.starts_with(v)))
        }
        "network" => {
            event.event_type == "network"
                && (event.actor_name == v
                    || event.actor_id == v
                    || event.attributes.get("name").is_some_and(|n| n == v))
        }
        "label" => {
            if let Some((lk, lv)) = v.split_once('=') {
                event.attributes.get(lk).is_some_and(|val| val == lv)
            } else {
                event.attributes.contains_key(v)
            }
        }
        _ => event.attributes.get(k).is_some_and(|val| val == v),
    }
}

pub fn matches_all_filters(event: &ContainerEvent, filters: &[String]) -> Result<bool> {
    if filters.is_empty() {
        return Ok(true);
    }
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for filt in filters {
        if let Some((k, v)) = filt.split_once('=') {
            let key = match k.trim() {
                "event" | "action" | "status" => "event".to_string(),
                other => other.to_string(),
            };
            grouped.entry(key).or_default().push(v.trim().to_string());
        } else {
            return Err(anyhow!(
                "failed to parse event filters: invalid filter {:?}",
                filt
            ));
        }
    }
    for (k, vals) in &grouped {
        let any_match = vals.iter().any(|v| match_single_filter_kv(event, k, v));
        if !any_match {
            return Ok(false);
        }
    }
    Ok(true)
}

fn format_event_with_template(event: &ContainerEvent, fmt: &str) -> String {
    if fmt == "json" || fmt == "{{json .}}" {
        return event.to_podman_stream_json();
    }
    let mut out = fmt.to_string();
    while let Some(start) = out.find("{{") {
        let Some(rel_end) = out[start..].find("}}") else {
            break;
        };
        let end = start + rel_end + 2;
        let inner = out[start + 2..end - 2].trim();
        let val = match inner {
            ".ID" | ".Id" => event.actor_id.clone(),
            ".Image" => event.attributes.get("image").cloned().unwrap_or_default(),
            ".Name" => event.actor_name.clone(),
            ".Status" | ".Action" => event.action.clone(),
            ".Type" => event.event_type.clone(),
            ".OOMKilled" => event
                .attributes
                .get("oomKilled")
                .or_else(|| event.attributes.get("OOMKilled"))
                .cloned()
                .unwrap_or_else(|| "false".to_string()),
            ".ContainerInspectData" => event
                .attributes
                .get("containerInspectData")
                .cloned()
                .unwrap_or_default(),
            ".Attributes" => {
                let mut pairs: Vec<String> = event
                    .attributes
                    .iter()
                    .filter(|(k, _)| k.as_str() != "containerInspectData")
                    .map(|(k, v)| format!("{}:{}", k, v))
                    .collect();
                pairs.sort();
                format!("map[{}]", pairs.join(" "))
            }
            other if other.starts_with(".Attributes.") => {
                let key = &other[".Attributes.".len()..];
                event.attributes.get(key).cloned().unwrap_or_default()
            }
            _ => String::new(),
        };
        out.replace_range(start..end, &val);
    }
    out
}

pub struct EventManager;

impl EventManager {
    fn events_file() -> PathBuf {
        let conf = load_events_conf();
        conf.logfile_path
            .unwrap_or_else(|| boxr_home().join("events.jsonl"))
    }

    pub fn is_container_create_inspect_data_enabled() -> bool {
        load_events_conf().container_create_inspect_data
    }

    pub fn last_died_exit_code(container: &str) -> Option<i32> {
        let path = Self::events_file();
        let content = fs::read_to_string(&path).ok()?;
        for line in content.lines().rev() {
            if let Some(ev) = parse_event_line(line.trim()) {
                if ev.event_type == "container"
                    && (ev.action == "died" || ev.action == "die")
                    && (ev.actor_name == container
                        || ev.actor_id == container
                        || (!container.is_empty() && ev.actor_id.starts_with(container)))
                {
                    if let Some(code_str) = ev.attributes.get("exitCode") {
                        if let Ok(code) = code_str.parse::<i32>() {
                            return Some(code);
                        }
                    }
                    return Some(0);
                }
            }
        }
        None
    }

    /// Record a lifecycle event to ~/.boxr/events.jsonl (or containers.conf events_logfile_path)
    pub fn record(event: ContainerEvent) {
        let conf = load_events_conf();
        if conf.logger.as_deref() == Some("none") {
            return;
        }
        if let Some(custom_path) = &conf.logfile_path {
            if let Some(max_size) = conf.max_size {
                rotate_podman_events_file_if_needed(custom_path, max_size);
            }
            append_podman_strict_event_line(custom_path, &event);
            return;
        }
        Self::record_to_sink(&event, &JsonlFileSink::new(Self::events_file()));
    }

    /// Record a lifecycle event to any EventSink (DIP)
    pub fn record_to_sink(event: &ContainerEvent, sink: &impl EventSink) {
        crate::guardrails::LogRotator::rotate_events_if_needed();
        let _ = sink.emit(event);
    }

    /// Stream or read recorded events
    pub fn stream_events(since: Option<&str>, filter: Option<&str>) -> Result<()> {
        let filters: Vec<String> = filter.into_iter().map(|s| s.to_string()).collect();
        Self::stream_events_with_options(since, None, &filters, None, false, false)
    }

    pub fn stream_events_with_options(
        since: Option<&str>,
        until: Option<&str>,
        filters: &[String],
        format: Option<&str>,
        stream: bool,
        no_trunc: bool,
    ) -> Result<()> {
        let conf = load_events_conf();
        if conf.logger.as_deref() == Some("none") {
            crate::cli::usage_errors::exit_usage_error(
                "cannot read events with the \"none\" backend",
            );
        }

        let since_dt = match since {
            Some(s) => match parse_event_timestamp(s) {
                Ok(dt) => Some(dt),
                Err(e) => crate::cli::usage_errors::exit_usage_error(e.to_string()),
            },
            None => None,
        };
        let until_dt = match until {
            Some(u) => match parse_event_timestamp(u) {
                Ok(dt) => Some(dt),
                Err(e) => crate::cli::usage_errors::exit_usage_error(e.to_string()),
            },
            None => None,
        };
        if let Err(e) = matches_all_filters(
            &ContainerEvent::new("container", "create", "", "", HashMap::new()),
            filters,
        ) {
            crate::cli::usage_errors::exit_usage_error(e.to_string());
        }

        let file_path = Self::events_file();
        if !file_path.exists() && !stream {
            return Ok(());
        }

        let is_test = cfg!(test);
        let mut empty_ticks = 0usize;
        let mut emitted_lines: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut initial_pass = true;

        loop {
            if file_path.exists() {
                if let Ok(file) = fs::File::open(&file_path) {
                    let reader = BufReader::new(file);
                    for line_res in reader.lines() {
                        let Ok(line) = line_res else {
                            break;
                        };
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let Some(event) = parse_event_line(trimmed) else {
                            continue;
                        };
                        if stream {
                            if !initial_pass
                                && event.event_type == "system"
                                && event.action == "log-rotation"
                                && event
                                    .attributes
                                    .get("io.podman.event.rotate")
                                    .is_some_and(|v| v == "begin")
                            {
                                continue;
                            }
                            if !emitted_lines.insert(trimmed.to_string()) {
                                continue;
                            }
                        }

                        if let Some(s_dt) = since_dt {
                            if event.timestamp < s_dt {
                                continue;
                            }
                        }
                        if let Some(u_dt) = until_dt {
                            if event.timestamp > u_dt {
                                continue;
                            }
                        }
                        if !matches_all_filters(&event, filters).unwrap_or(false) {
                            continue;
                        }
                        let out_line = if let Some(fmt) = format {
                            format_event_with_template(&event, fmt)
                        } else {
                            event.display_line_with_trunc(no_trunc)
                        };
                        println!("{}", out_line);
                        let _ = std::io::stdout().flush();
                    }
                }
            }
            initial_pass = false;
            if !stream {
                break;
            }
            empty_ticks += 1;
            if is_test && empty_ticks > 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_formatting() {
        let mut attrs = HashMap::new();
        attrs.insert("image".to_string(), "alpine:latest".to_string());
        attrs.insert("name".to_string(), "my-container".to_string());

        let event =
            ContainerEvent::new("container", "start", "1234567890ab", "my-container", attrs);
        let line = event.display_line();

        assert!(line.contains("container start 1234567890ab"));
        assert!(line.contains("image=alpine:latest"));
    }

    #[test]
    fn test_event_filter_key_value_matching() {
        let mut attrs = HashMap::new();
        attrs.insert("image".to_string(), "alpine:latest".to_string());
        let event = ContainerEvent::new("container", "create", "c123", "test-box", attrs);

        let match_filter = |event: &ContainerEvent, filt: &str| -> bool {
            if let Some((k, v)) = filt.split_once('=') {
                match k.trim() {
                    "event" | "action" => event.action == v.trim(),
                    "type" => event.event_type == v.trim(),
                    "container" | "image" => {
                        event.actor_name == v.trim() || event.actor_id.starts_with(v.trim())
                    }
                    _ => event
                        .attributes
                        .get(k.trim())
                        .map(|val| val == v.trim())
                        .unwrap_or(false),
                }
            } else {
                event.event_type.contains(filt)
                    || event.action.contains(filt)
                    || event.actor_name.contains(filt)
            }
        };

        assert!(match_filter(&event, "event=create"));
        assert!(match_filter(&event, "type=container"));
        assert!(match_filter(&event, "container=test-box"));
        assert!(!match_filter(&event, "event=die"));
        assert!(!match_filter(&event, "container=other"));
    }
}
