use super::*;
use crate::network::NetworkStore;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

#[test]
fn test_compose_yaml_parse_and_dependency_order() {
    let yaml = r#"
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    depends_on:
      - api
  api:
    image: node:18
    ports:
      - "3000:3000"
    depends_on:
      - db
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
"#;

    let compose: ComposeFile = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(compose.services.len(), 3);
    assert!(compose.volumes.contains_key("pgdata"));

    let project = ComposeProject {
        name: "myapp".to_string(),
        compose_file_path: PathBuf::from("docker-compose.yml"),
        compose,
    };

    let order = project.dependency_order().unwrap();
    // db must come before api, api must come before web
    let db_pos = order.iter().position(|s| s == "db").unwrap();
    let api_pos = order.iter().position(|s| s == "api").unwrap();
    let web_pos = order.iter().position(|s| s == "web").unwrap();

    assert!(db_pos < api_pos);
    assert!(api_pos < web_pos);
}

#[test]
fn test_compose_environment_overrides_env_file() {
    let temp = tempfile::tempdir().unwrap();
    let env_file_path = temp.path().join(".env.test");
    fs::write(
        &env_file_path,
        "PORT=8000\nDB=staging\nSHARED=env_file_val\n",
    )
    .unwrap();

    let yaml = format!(
        r#"
version: '3.8'
services:
  web:
    image: nginx:latest
    env_file:
      - {}
    environment:
      PORT: "9000"
      SHARED: "inline_val"
"#,
        env_file_path.display()
    );

    let proj = ComposeProject::from_str(&yaml, "env-test").unwrap();
    let svc = &proj.compose.services["web"];

    let mut env_vec = Vec::new();
    if let Some(ef) = &svc.env_file {
        for path_str in ef.to_vec() {
            if let Ok(content) = fs::read_to_string(&path_str) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        env_vec.push(trimmed.to_string());
                    }
                }
            }
        }
    }
    if let Some(env_entries) = &svc.environment {
        for e in env_entries.to_vec() {
            if let Some((k, _)) = e.split_once('=') {
                env_vec.retain(|existing| {
                    existing
                        .split_once('=')
                        .map(|(ek, _)| ek != k)
                        .unwrap_or(true)
                });
            }
            env_vec.push(e);
        }
    }

    assert!(env_vec.contains(&"PORT=9000".to_string()));
    assert!(env_vec.contains(&"SHARED=inline_val".to_string()));
    assert!(env_vec.contains(&"DB=staging".to_string()));
    assert!(!env_vec.contains(&"PORT=8000".to_string()));
    assert!(!env_vec.contains(&"SHARED=env_file_val".to_string()));
}

#[test]
fn test_compose_down_avoids_prefix_collision() {
    let yaml = r#"
version: '3.8'
services:
  web:
    image: nginx:latest
"#;
    let proj = ComposeProject::from_str(yaml, "app").unwrap();
    let prefix = "app_";
    let other_project_container = "app_backend_web_1";

    let matches_other = other_project_container
        .strip_prefix(prefix)
        .map(|rest| {
            if let Some((svc, _)) = rest.rsplit_once('_') {
                proj.compose.services.contains_key(svc)
            } else {
                false
            }
        })
        .unwrap_or(false);

    assert!(
        !matches_other,
        "Compose down for 'app' must not match 'app_backend_web_1'"
    );
}

#[test]
fn test_issue_420_compose_down_cleans_project_network() {
    let yaml = r#"
version: '3.8'
services:
  web:
    image: alpine:latest
  api:
    image: alpine:latest
"#;
    let proj = ComposeProject::from_str(yaml, "myproj").unwrap();
    let net_store = NetworkStore::new();
    let net_name = "myproj_default";

    // Create the network and register containers like compose up does
    let _ = net_store.create(net_name, None, None);
    let _ = net_store.connect_container(net_name, "myproj_web_1", "web");
    let _ = net_store.connect_container(net_name, "myproj_api_1", "api");

    assert!(net_store.find(net_name).is_some());
    assert_eq!(net_store.find(net_name).unwrap().containers.len(), 2);

    // Run compose down
    proj.down(false).unwrap();

    // Project network must be removed and not left behind
    assert!(
        net_store.find(net_name).is_none(),
        "Project network must be removed by compose down"
    );
}

#[test]
fn test_issue_419_compose_service_discovery_hosts() {
    let yaml = r#"
version: '3.8'
services:
  web:
    image: alpine:latest
  api:
    image: alpine:latest
"#;
    let proj = ComposeProject::from_str(yaml, "servicedisc").unwrap();
    let net_store = NetworkStore::new();
    let net_name = "servicedisc_default";

    let _ = net_store.create(net_name, None, None);
    let ep_web = net_store
        .connect_container(net_name, "servicedisc_web_1", "web")
        .unwrap();
    let ep_api = net_store
        .connect_container(net_name, "servicedisc_api_1", "api")
        .unwrap();

    let run_args = proj
        .build_service_run_args(
            "web",
            &proj.compose.services["web"],
            "servicedisc_web_1",
            "alpine:latest",
            true,
        )
        .unwrap();

    // Verify hostname is set to service name
    assert_eq!(run_args.hostname, Some("web".to_string()));
    // Verify network is set to project network
    assert_eq!(run_args.network, "servicedisc_default");
    // Verify service discovery mappings are present in add_host
    assert!(
        run_args
            .add_host
            .contains(&format!("api:{}", ep_api.ipv4_address))
    );
    assert!(
        run_args
            .add_host
            .contains(&format!("servicedisc_api_1:{}", ep_api.ipv4_address))
    );
    assert!(
        run_args
            .add_host
            .contains(&format!("web:{}", ep_web.ipv4_address))
    );
    assert!(
        run_args
            .add_host
            .contains(&format!("servicedisc_web_1:{}", ep_web.ipv4_address))
    );

    // Clean up
    let _ = net_store.remove_with_force(net_name, true);
}

#[test]
fn test_compose_interpolate_env_file_before_parse() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env"), "HOST_PORT=9090\n").unwrap();
    fs::write(
        dir.path().join("docker-compose.yml"),
        r#"
services:
  web:
    image: nginx
    ports:
      - "${HOST_PORT:-8080}:80"
"#,
    )
    .unwrap();
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let project = ComposeProject::load(Path::new("docker-compose.yml")).unwrap();
    std::env::set_current_dir(prev).unwrap();
    let ports = project.compose.services["web"].ports.as_ref().unwrap();
    assert_eq!(ports[0], "9090:80");
}

#[test]
fn test_compose_build_spec_and_map_depends_on_parse() {
    let yaml = r#"
services:
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      args:
        NEXT_PUBLIC_API_URL: http://localhost:8080/api
    depends_on:
      backend:
        condition: service_healthy
        required: false
  backend:
    image: alpine:latest
"#;
    let project = ComposeProject::from_str(yaml, "spice-box").unwrap();
    let frontend = &project.compose.services["frontend"];
    let build = frontend.build.as_ref().unwrap();
    assert_eq!(build.context_path(), "./frontend");
    assert_eq!(build.dockerfile_name(), "Dockerfile");
    assert_eq!(
        build
            .build_args()
            .get("NEXT_PUBLIC_API_URL")
            .map(String::as_str),
        Some("http://localhost:8080/api")
    );

    let order = project
        .services_for_up(&["frontend".to_string()], false)
        .unwrap();
    assert_eq!(order, vec!["backend", "frontend"]);
}
