use std::path::Path;

pub struct DockerIgnore {
    patterns: Vec<String>,
}

impl DockerIgnore {
    pub fn load_from_context(context_dir: &Path) -> Self {
        Self::load_with_override(context_dir, None)
    }

    pub fn load_with_override(context_dir: &Path, override_file: Option<&Path>) -> Self {
        let ignore_path = if let Some(ov) = override_file {
            Some(ov.to_path_buf())
        } else if context_dir.join(".containerignore").exists() {
            Some(context_dir.join(".containerignore"))
        } else if context_dir.join(".dockerignore").exists() {
            Some(context_dir.join(".dockerignore"))
        } else {
            None
        };

        if let Some(ignore_file) = ignore_path {
            if let Ok(content) = std::fs::read_to_string(&ignore_file) {
                let patterns: Vec<String> = content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                return Self { patterns };
            }
        }
        Self {
            patterns: Vec::new(),
        }
    }

    fn eval_direct(&self, path_str: &str) -> bool {
        let mut ignored = false;
        for p in &self.patterns {
            if let Some(exception) = p.strip_prefix('!') {
                let ex = exception.trim().trim_start_matches('/').trim_end_matches('/');
                if pattern_matches(ex, path_str) {
                    ignored = false;
                }
            } else {
                let pat = p.trim().trim_start_matches('/').trim_end_matches('/');
                if pattern_matches(pat, path_str) {
                    ignored = true;
                }
            }
        }
        ignored
    }

    pub fn is_ignored(&self, rel_path: &Path) -> bool {
        let raw = rel_path.to_string_lossy();
        let path_str = raw
            .trim_start_matches("./")
            .trim_start_matches('/')
            .trim_end_matches('/');
        if path_str.is_empty() || path_str == "." {
            return false;
        }

        // Check parent directory prefixes: if a parent dir is ignored and no negation pattern
        // explicitly starts with `<parent>/`, Buildah skips descending into `<parent>`.
        let parts: Vec<&str> = path_str.split('/').collect();
        if parts.len() > 1 {
            let mut prefix = String::new();
            for part in &parts[..parts.len() - 1] {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                if self.eval_direct(&prefix) {
                    let prefix_slash = format!("{}/", prefix);
                    let has_explicit_child_negation = self.patterns.iter().any(|p| {
                        p.strip_prefix('!')
                            .map(|ex| ex.trim().trim_start_matches('/'))
                            .is_some_and(|ex| ex.starts_with(&prefix_slash))
                    });
                    if !has_explicit_child_negation {
                        return true;
                    }
                }
            }
        }

        self.eval_direct(path_str)
    }
}

fn pattern_matches(pattern: &str, path: &str) -> bool {
    let p = pattern.trim_start_matches('/').trim_end_matches('/');
    if p.is_empty() {
        return false;
    }
    if matches_wildcard(p, path) {
        return true;
    }
    if path.starts_with(&format!("{}/", p)) {
        return true;
    }
    for (idx, _) in path.match_indices('/') {
        let prefix = &path[..idx];
        if matches_wildcard(p, prefix) {
            return true;
        }
    }
    false
}

pub fn matches_wildcard(pattern: &str, text: &str) -> bool {
    let p_chars: Vec<char> = pattern.chars().collect();
    let t_chars: Vec<char> = text.chars().collect();
    let mut p = 0;
    let mut t = 0;
    let mut star = None;
    let mut match_idx = 0;

    while t < t_chars.len() {
        if p < p_chars.len() && (p_chars[p] == '?' || p_chars[p] == t_chars[t]) {
            p += 1;
            t += 1;
        } else if p < p_chars.len() && p_chars[p] == '*' {
            star = Some(p);
            match_idx = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            match_idx += 1;
            t = match_idx;
        } else {
            return false;
        }
    }
    while p < p_chars.len() && p_chars[p] == '*' {
        p += 1;
    }
    p == p_chars.len()
}
