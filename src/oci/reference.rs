use anyhow::{Result, anyhow};
use std::fmt;

/// An image reference parsed into its constituent parts according to OCI conventions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: Option<String>,
}

impl ImageReference {
    /// Default registry for unqualified images.
    pub const DEFAULT_REGISTRY: &'static str = "registry-1.docker.io";
    /// Default tag if none is specified.
    pub const DEFAULT_TAG: &'static str = "latest";

    /// Parse a string reference such as "hello-world", "alpine:3.19", or "ghcr.io/org/repo:tag".
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(anyhow!("Empty image reference"));
        }
        // A reference never legitimately ends with a slash; accepting one
        // creates un-addressable image records (issue #402).
        if input.ends_with('/') {
            return Err(anyhow!(
                "Invalid image reference '{}': trailing slash",
                input
            ));
        }

        // Check for digest first: name@sha256:xxx
        let (remainder, digest) = if let Some(idx) = input.find('@') {
            let (name, digest_part) = input.split_at(idx);
            let digest_str = &digest_part[1..];
            if digest_str.is_empty() {
                return Err(anyhow!("Invalid image reference '{}': empty digest", input));
            }
            (name, Some(digest_str.to_string()))
        } else {
            (input, None)
        };

        // Check for tag: name:tag
        // Note: A port in the registry (e.g., localhost:5000/repo:tag) must not be confused with a tag
        let (name_part, tag) = if let Some(colon_idx) = remainder.rfind(':') {
            // If the colon is before the first slash, it's a port, not a tag
            if let Some(slash_idx) = remainder.find('/') {
                if colon_idx < slash_idx {
                    (remainder, Self::DEFAULT_TAG.to_string())
                } else {
                    (
                        &remainder[..colon_idx],
                        remainder[colon_idx + 1..].to_string(),
                    )
                }
            } else {
                (
                    &remainder[..colon_idx],
                    remainder[colon_idx + 1..].to_string(),
                )
            }
        } else {
            (remainder, Self::DEFAULT_TAG.to_string())
        };

        // Reject empty repository names and empty tags (issue #406):
        // ":latest" and "alpine:" must not parse.
        if name_part.is_empty() {
            return Err(anyhow!(
                "Invalid image reference '{}': repository name cannot be empty",
                input
            ));
        }
        if tag.is_empty() {
            return Err(anyhow!("Invalid image reference '{}': empty tag", input));
        }

        // Parse registry and repository
        let (registry, repository) = if let Some(slash_idx) = name_part.find('/') {
            let potential_registry = &name_part[..slash_idx];
            if potential_registry == "docker.io"
                || potential_registry == "index.docker.io"
                || potential_registry == "registry-1.docker.io"
            {
                (
                    Self::DEFAULT_REGISTRY.to_string(),
                    name_part[slash_idx + 1..].to_string(),
                )
            } else if potential_registry.contains('.')
                || potential_registry.contains(':')
                || potential_registry == "localhost"
            {
                (
                    potential_registry.to_string(),
                    name_part[slash_idx + 1..].to_string(),
                )
            } else {
                // Docker Hub official/user repo like "library/hello-world" or "myuser/myimage"
                (Self::DEFAULT_REGISTRY.to_string(), name_part.to_string())
            }
        } else {
            // Official library image on Docker Hub
            (
                Self::DEFAULT_REGISTRY.to_string(),
                format!("library/{}", name_part),
            )
        };

        // If repository still doesn't have a slash and registry is docker.io, prefix with library/
        let repository = if registry == Self::DEFAULT_REGISTRY && !repository.contains('/') {
            format!("library/{}", repository)
        } else {
            repository
        };

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Full canonical name (e.g. "registry-1.docker.io/library/hello-world:latest")
    #[allow(dead_code)]
    pub fn canonical(&self) -> String {
        format!("{}/{}:{}", self.registry, self.repository, self.tag)
    }

    /// Short human-readable display name (e.g. "hello-world:latest").
    /// Digest-pinned references keep their digest (issue #405), e.g.
    /// "alpine@sha256:abc..." instead of collapsing to "alpine:latest".
    pub fn display_name(&self) -> String {
        let name = if self.registry == Self::DEFAULT_REGISTRY {
            if let Some(stripped) = self.repository.strip_prefix("library/") {
                stripped.to_string()
            } else {
                self.repository.clone()
            }
        } else {
            format!("{}/{}", self.registry, self.repository)
        };
        match &self.digest {
            Some(d) if self.tag == Self::DEFAULT_TAG => format!("{}@{}", name, d),
            Some(d) => format!("{}:{}@{}", name, self.tag, d),
            None => format!("{}:{}", name, self.tag),
        }
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let r = ImageReference::parse("hello-world").unwrap();
        assert_eq!(r.registry, ImageReference::DEFAULT_REGISTRY);
        assert_eq!(r.repository, "library/hello-world");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn test_parse_with_tag() {
        let r = ImageReference::parse("alpine:3.19").unwrap();
        assert_eq!(r.registry, ImageReference::DEFAULT_REGISTRY);
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, "3.19");
    }

    #[test]
    fn test_parse_custom_registry() {
        let r = ImageReference::parse("ghcr.io/org/repo:v1.0").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/repo");
        assert_eq!(r.tag, "v1.0");
    }

    #[test]
    fn test_parse_digest() {
        let r = ImageReference::parse("alpine@sha256:abcdef").unwrap();
        assert_eq!(r.digest.as_deref(), Some("sha256:abcdef"));
    }

    #[test]
    fn test_parse_docker_io_normalization() {
        let r1 = ImageReference::parse("docker.io/library/alpine:latest").unwrap();
        assert_eq!(r1.registry, ImageReference::DEFAULT_REGISTRY);
        assert_eq!(r1.repository, "library/alpine");

        let r2 = ImageReference::parse("docker.io/alpine:latest").unwrap();
        assert_eq!(r2.registry, ImageReference::DEFAULT_REGISTRY);
        assert_eq!(r2.repository, "library/alpine");

        let r3 = ImageReference::parse("index.docker.io/user/app:v1").unwrap();
        assert_eq!(r3.registry, ImageReference::DEFAULT_REGISTRY);
        assert_eq!(r3.repository, "user/app");
    }

    // Issue #402: trailing-slash references must be rejected, not stored.
    #[test]
    fn test_issue_402_rejects_trailing_slash() {
        assert!(ImageReference::parse("alpine:latest/").is_err());
        assert!(ImageReference::parse("alpine/").is_err());
        assert!(ImageReference::parse("ghcr.io/org/repo:1.0/").is_err());
        assert!(ImageReference::parse("localhost:5000/my-image:v1/").is_err());
        // Sanity: the same references without the slash still parse.
        assert!(ImageReference::parse("alpine:latest").is_ok());
        assert!(ImageReference::parse("alpine").is_ok());
    }

    // Issue #406: empty repository names and empty tags must be rejected.
    #[test]
    fn test_issue_406_rejects_empty_name_and_tag() {
        assert!(ImageReference::parse(":latest").is_err());
        assert!(ImageReference::parse("alpine:").is_err());
        assert!(ImageReference::parse("@sha256:abcdef").is_err());
        assert!(ImageReference::parse("alpine@").is_err());
        assert!(ImageReference::parse("").is_err());
        assert!(ImageReference::parse("   ").is_err());
        // Sanity: valid references still parse.
        assert!(ImageReference::parse("alpine:latest").is_ok());
        assert!(ImageReference::parse("alpine@sha256:abcdef").is_ok());
    }

    // Issue #405: digest-pinned pulls must keep the digest in display output.
    #[test]
    fn test_issue_405_display_name_preserves_digest() {
        let r = ImageReference::parse("alpine@sha256:abcdef123456").unwrap();
        assert_eq!(r.display_name(), "alpine@sha256:abcdef123456");

        let r = ImageReference::parse("alpine:3.19@sha256:abcdef123456").unwrap();
        assert_eq!(r.display_name(), "alpine:3.19@sha256:abcdef123456");

        let r = ImageReference::parse("ghcr.io/org/repo@sha256:abcdef123456").unwrap();
        assert_eq!(r.display_name(), "ghcr.io/org/repo@sha256:abcdef123456");

        // Non-digest references are unchanged.
        let r = ImageReference::parse("alpine").unwrap();
        assert_eq!(r.display_name(), "alpine:latest");
        let r = ImageReference::parse("ghcr.io/org/repo:1.0").unwrap();
        assert_eq!(r.display_name(), "ghcr.io/org/repo:1.0");
    }
}
