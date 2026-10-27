//! Docker / Podman Compose file variable substitution.
//!
//! See: https://docs.docker.com/compose/how-tos/environment-variables/variable-substitution/

use anyhow::{Result, bail};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Placeholder for `$$` so later interpolation passes do not expand the escaped `$`.
const LITERAL_DOLLAR: char = '\u{e000}';

/// Build the substitution environment: `.env` in the project directory, then process
/// environment (process values override `.env`, matching Compose).
pub fn project_env(project_dir: &Path) -> HashMap<String, String> {
    let mut env = load_dotenv(&project_dir.join(".env"));
    for (key, value) in std::env::vars() {
        env.insert(key, value);
    }
    env
}

/// Walk a parsed YAML tree and interpolate string scalars in place.
pub fn interpolate_yaml(
    value: &mut serde_yaml::Value,
    env: &HashMap<String, String>,
) -> Result<()> {
    match value {
        serde_yaml::Value::String(s) => {
            *s = interpolate(s, env)?;
        }
        serde_yaml::Value::Mapping(map) => {
            for v in map.values_mut() {
                interpolate_yaml(v, env)?;
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq.iter_mut() {
                interpolate_yaml(v, env)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Interpolate `$VAR` / `${VAR}` references until fixed point (Compose re-expands).
pub fn interpolate(input: &str, env: &HashMap<String, String>) -> Result<String> {
    let mut current = input.to_string();
    for _ in 0..32 {
        let next = interpolate_once(&current, env)?;
        if next == current {
            return Ok(current.replace(LITERAL_DOLLAR, "$"));
        }
        current = next;
    }
    bail!("compose variable substitution did not converge after 32 passes");
}

fn interpolate_once(input: &str, env: &HashMap<String, String>) -> Result<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '$' {
            if i + 1 < chars.len() && chars[i + 1] == '$' {
                out.push(LITERAL_DOLLAR);
                i += 2;
                continue;
            }
            if i + 1 < chars.len() && chars[i + 1] == '{' {
                let start = i + 2;
                let mut j = start;
                while j < chars.len() && chars[j] != '}' {
                    j += 1;
                }
                if j >= chars.len() {
                    out.push('$');
                    i += 1;
                    continue;
                }
                let inner: String = chars[start..j].iter().collect();
                out.push_str(&expand_braced(&inner, env)?);
                i = j + 1;
                continue;
            }
            if i + 1 < chars.len() && is_var_start(chars[i + 1]) {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && is_var_char(chars[j]) {
                    j += 1;
                }
                let name: String = chars[start..j].iter().collect();
                out.push_str(env.get(&name).map(String::as_str).unwrap_or(""));
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    Ok(out)
}

fn is_var_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

fn is_var_char(c: char) -> bool {
    is_var_start(c) || c.is_ascii_digit()
}

fn expand_braced(inner: &str, env: &HashMap<String, String>) -> Result<String> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(String::new());
    }

    const MODIFIERS: [(&str, Modifier); 6] = [
        (":-", Modifier::DefaultUnsetOrEmpty),
        ("-", Modifier::DefaultUnset),
        (":+", Modifier::AltIfNonempty),
        ("+", Modifier::AltIfSet),
        (":?", Modifier::RequiredUnsetOrEmpty),
        ("?", Modifier::RequiredUnset),
    ];

    for (sep, modifier) in MODIFIERS {
        if let Some(idx) = inner.find(sep) {
            let name = inner[..idx].trim();
            if name.is_empty() {
                bail!(
                    "invalid compose substitution: empty variable name in '${{{}}}'",
                    inner
                );
            }
            let operand = inner[idx + sep.len()..].to_string();
            return apply_modifier(name, operand, modifier, env);
        }
    }

    let name = inner;
    Ok(env.get(name).cloned().unwrap_or_default())
}

#[derive(Clone, Copy)]
enum Modifier {
    DefaultUnsetOrEmpty,
    DefaultUnset,
    AltIfNonempty,
    AltIfSet,
    RequiredUnsetOrEmpty,
    RequiredUnset,
}

fn apply_modifier(
    name: &str,
    operand: String,
    modifier: Modifier,
    env: &HashMap<String, String>,
) -> Result<String> {
    let value = env.get(name);
    match modifier {
        Modifier::DefaultUnsetOrEmpty => {
            if value.is_none() || value.is_some_and(|v| v.is_empty()) {
                Ok(operand)
            } else {
                Ok(value.unwrap().clone())
            }
        }
        Modifier::DefaultUnset => {
            if value.is_none() {
                Ok(operand)
            } else {
                Ok(value.unwrap().clone())
            }
        }
        Modifier::AltIfNonempty => {
            if value.is_some_and(|v| !v.is_empty()) {
                Ok(operand)
            } else {
                Ok(String::new())
            }
        }
        Modifier::AltIfSet => {
            if value.is_some() {
                Ok(operand)
            } else {
                Ok(String::new())
            }
        }
        Modifier::RequiredUnsetOrEmpty => {
            if value.is_none() || value.is_some_and(|v| v.is_empty()) {
                bail!(
                    "{}",
                    if operand.is_empty() {
                        format!("required variable {} is missing a value", name)
                    } else {
                        operand
                    }
                );
            }
            Ok(value.unwrap().clone())
        }
        Modifier::RequiredUnset => {
            if value.is_none() {
                bail!(
                    "{}",
                    if operand.is_empty() {
                        format!("required variable {} is not set", name)
                    } else {
                        operand
                    }
                );
            }
            Ok(value.unwrap().clone())
        }
    }
}

/// Parse a Compose `.env` file (KEY=VALUE lines; optional `export` prefix).
pub fn load_dotenv(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return map,
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut line = trimmed;
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim();
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = parse_dotenv_value(raw_value.trim());
        map.insert(key.to_string(), value);
    }
    map
}

fn parse_dotenv_value(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if (raw.starts_with('"') && raw.ends_with('"'))
        || (raw.starts_with('\'') && raw.ends_with('\''))
    {
        return raw[1..raw.len() - 1].to_string();
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_default_unset_or_empty() {
        let env = env_map(&[("PORT", "3000")]);
        assert_eq!(
            interpolate("host: ${PORT:-8080}", &env).unwrap(),
            "host: 3000"
        );
        let env = env_map(&[("PORT", "")]);
        assert_eq!(
            interpolate("host: ${PORT:-8080}", &env).unwrap(),
            "host: 8080"
        );
        assert_eq!(
            interpolate("host: ${MISSING:-8080}", &env_map(&[])).unwrap(),
            "host: 8080"
        );
    }

    #[test]
    fn test_default_unset_only() {
        let env = env_map(&[("PORT", "")]);
        assert_eq!(interpolate("${PORT-8080}", &env).unwrap(), "");
        assert_eq!(
            interpolate("${MISSING-8080}", &env_map(&[])).unwrap(),
            "8080"
        );
    }

    #[test]
    fn test_escape_dollar() {
        assert_eq!(
            interpolate("cost is $$VAR", &env_map(&[])).unwrap(),
            "cost is $VAR"
        );
    }

    #[test]
    fn test_bare_variable() {
        let env = env_map(&[("FOO", "bar")]);
        assert_eq!(interpolate("$FOO/baz", &env).unwrap(), "bar/baz");
    }

    #[test]
    fn test_port_mapping_line() {
        let env = env_map(&[]);
        assert_eq!(
            interpolate("${POSTGRES_PORT:-5432}:5432", &env).unwrap(),
            "5432:5432"
        );
    }

    #[test]
    fn test_required_modifier_errors() {
        let err = interpolate("${NEED:?must set NEED}", &env_map(&[])).unwrap_err();
        assert!(err.to_string().contains("must set NEED"));
    }

    #[test]
    fn test_load_dotenv_quoted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "export FOO=bar\nQUOTED=\"hello world\"\n# comment\nBAD\n",
        )
        .unwrap();
        let map = load_dotenv(&dir.path().join(".env"));
        assert_eq!(map.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(map.get("QUOTED").map(String::as_str), Some("hello world"));
        assert!(!map.contains_key("BAD"));
    }

    #[test]
    fn test_alt_modifiers() {
        let env = env_map(&[("SET", "x")]);
        assert_eq!(interpolate("${SET:+yes}", &env).unwrap(), "yes");
        assert_eq!(interpolate("${UNSET:+yes}", &env).unwrap(), "");
        assert_eq!(
            interpolate("${SET+yes}", &env_map(&[("SET", "")])).unwrap(),
            "yes"
        );
    }
}
