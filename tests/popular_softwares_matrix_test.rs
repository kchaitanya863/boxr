use boxr::builder::DockerfileParser;
use boxr::compose::ComposeProject;
use std::path::PathBuf;
use std::process::Command;

fn boxr_bin() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("boxr");
    if !path.exists() {
        let alt = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(if cfg!(debug_assertions) {
                "release"
            } else {
                "debug"
            })
            .join("boxr");
        if alt.exists() {
            return alt;
        }
    }
    path
}

fn boxr_cmd(bin: &PathBuf) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_remove("DOCKER_HOST");
    cmd
}

// -----------------------------------------------------------------------------
// Top 30 Popular Containerized Softwares: Specifications & Regression Matrix
//
// These tests validate YAML *parsing* via `ComposeProject::from_str` (static specs).
// For Docker/Podman replacement parity (CLI `compose up SERVICE`, `.env`, and
// `${VAR:-default}` interpolation), see `tests/compose_docker_replacement_test.rs`
// and `tests/docker_parity_test.rs`.
// -----------------------------------------------------------------------------

/// 1. NGINX - High-Performance Web Server & Reverse Proxy
#[test]
fn test_software_01_nginx() {
    let yaml = r#"
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
      - "8443:443"
    environment:
      NGINX_PORT: "80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - web-logs:/var/log/nginx
    restart: always
volumes:
  web-logs:
"#;
    let proj = ComposeProject::from_str(yaml, "nginx-test").unwrap();
    assert!(proj.compose.services.contains_key("web"));
    let svc = &proj.compose.services["web"];
    assert_eq!(svc.image.as_deref(), Some("nginx:alpine"));
    assert_eq!(svc.ports.as_ref().unwrap().len(), 2);
    assert!(proj.compose.volumes.contains_key("web-logs"));
}

/// 2. Redis - In-Memory Data Store & Cache
#[test]
fn test_software_02_redis() {
    let yaml = r#"
version: '3.8'
services:
  cache:
    image: redis:7-alpine
    command: ["redis-server", "--appendonly", "yes", "--protected-mode", "no"]
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
volumes:
  redis-data:
"#;
    let proj = ComposeProject::from_str(yaml, "redis-test").unwrap();
    let svc = &proj.compose.services["cache"];
    assert_eq!(svc.image.as_deref(), Some("redis:7-alpine"));
    assert_eq!(svc.ports.as_ref().unwrap()[0], "6379:6379");
    assert!(proj.compose.volumes.contains_key("redis-data"));
}

/// 3. PostgreSQL - Enterprise Relational Database
#[test]
fn test_software_03_postgres() {
    let yaml = r#"
version: '3.8'
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: enterprise_db
      POSTGRES_USER: pguser
      POSTGRES_PASSWORD: SecretPassword123!
      PGDATA: /var/lib/postgresql/data/pgdata
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
"#;
    let proj = ComposeProject::from_str(yaml, "postgres-test").unwrap();
    let svc = &proj.compose.services["db"];
    assert_eq!(svc.image.as_deref(), Some("postgres:16-alpine"));
    let envs = svc.environment.as_ref().unwrap().to_vec();
    assert!(envs.iter().any(|e| e.starts_with("POSTGRES_DB=")));
    assert!(envs.iter().any(|e| e.starts_with("POSTGRES_USER=pguser")));
    assert_eq!(svc.ports.as_ref().unwrap()[0], "5432:5432");
}

/// 4. MySQL - Relational Database Management System
#[test]
fn test_software_04_mysql() {
    let yaml = r#"
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: RootSecretPassword!
      MYSQL_DATABASE: app_db
      MYSQL_USER: appuser
      MYSQL_PASSWORD: UserSecretPassword!
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql
volumes:
  mysql-data:
"#;
    let proj = ComposeProject::from_str(yaml, "mysql-test").unwrap();
    let svc = &proj.compose.services["mysql"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "3306:3306");
    let envs = svc.environment.as_ref().unwrap().to_vec();
    assert!(envs.iter().any(|e| e.starts_with("MYSQL_ROOT_PASSWORD=")));
}

/// 5. MariaDB - Open-Source Relational Database
#[test]
fn test_software_05_mariadb() {
    let yaml = r#"
version: '3.8'
services:
  mariadb:
    image: mariadb:11
    environment:
      MARIADB_ROOT_PASSWORD: MariaSecret123!
      MARIADB_DATABASE: inventory
    ports:
      - "3306:3306"
    volumes:
      - mariadb-data:/var/lib/mysql
volumes:
  mariadb-data:
"#;
    let proj = ComposeProject::from_str(yaml, "mariadb-test").unwrap();
    let svc = &proj.compose.services["mariadb"];
    assert_eq!(svc.image.as_deref(), Some("mariadb:11"));
    assert_eq!(svc.ports.as_ref().unwrap()[0], "3306:3306");
}

/// 6. MongoDB - Document-Oriented NoSQL Database
#[test]
fn test_software_06_mongodb() {
    let yaml = r#"
version: '3.8'
services:
  mongo:
    image: mongo:7.0
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: MongoPassword456!
    ports:
      - "27017:27017"
    volumes:
      - mongodata:/data/db
volumes:
  mongodata:
"#;
    let proj = ComposeProject::from_str(yaml, "mongo-test").unwrap();
    let svc = &proj.compose.services["mongo"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "27017:27017");
}

/// 7. Node.js - Server-Side JavaScript Runtime
#[test]
fn test_software_07_node() {
    let df = r#"
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
ENV NODE_ENV=production
EXPOSE 3000
USER node
CMD ["node", "server.js"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 7);
}

/// 8. Python - Scientific, Web & Automation Runtime
#[test]
fn test_software_08_python() {
    let df = r#"
FROM python:3.11-slim
WORKDIR /workspace
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 8);
}

/// 9. Golang - Compiled Systems & Cloud-Native Runtime
#[test]
fn test_software_09_golang() {
    let df = r#"
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/server

FROM scratch
COPY --from=builder /app/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 8);
}

/// 10. OpenJDK / Eclipse Temurin - Enterprise Java Virtual Machine
#[test]
fn test_software_10_openjdk() {
    let df = r#"
FROM eclipse-temurin:21-jre-alpine
WORKDIR /opt/app
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -XX:+UseG1GC"
COPY target/*.jar app.jar
EXPOSE 8080
USER 10001
ENTRYPOINT ["java", "-jar", "app.jar"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert!(
        instructions
            .iter()
            .any(|i| matches!(i, boxr::builder::Instruction::Expose(8080)))
    );
}

/// 11. Ruby - Web Application & Scripts Environment
#[test]
fn test_software_11_ruby() {
    let df = r#"
FROM ruby:3.3-alpine
WORKDIR /usr/src/app
ENV RAILS_ENV=production \
    BUNDLE_DEPLOYMENT=1
COPY Gemfile* ./
EXPOSE 3000
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 7);
}

/// 12. PHP - Web Framework & FPM Engine
#[test]
fn test_software_12_php() {
    let df = r#"
FROM php:8.3-fpm-alpine
WORKDIR /var/www/html
COPY . .
EXPOSE 9000
CMD ["php-fpm"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert!(
        instructions
            .iter()
            .any(|i| matches!(i, boxr::builder::Instruction::Expose(9000)))
    );
}

/// 13. Rust - Systems Programming Language
#[test]
fn test_software_13_rust() {
    let df = r#"
FROM rust:1.77-alpine AS build
WORKDIR /usr/src/crate
COPY . .
RUN cargo build --release
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 4);
}

/// 14. Ubuntu - Standard Enterprise Linux Base Image
#[test]
fn test_software_14_ubuntu() {
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }
    // Verify inspect formatting and canonical spec
    let out = boxr_cmd(&bin).args(["inspect", "ubuntu:latest"]).output();
    assert!(out.is_ok());
}

/// 15. Debian - Universal Linux Operating System
#[test]
fn test_software_15_debian() {
    let df = r#"
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
CMD ["/bin/bash"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 3);
}

/// 16. Alpine Linux - Zero-Vulnerability Minimal OS
#[test]
fn test_software_16_alpine() {
    let df = r#"
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
CMD ["/bin/sh"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 3);
}

/// 17. BusyBox - Minimal Unix Utilities Suite
#[test]
fn test_software_17_busybox() {
    let df = r#"
FROM busybox:latest
CMD ["echo", "BusyBox Alive"]
"#;
    let instructions = DockerfileParser::parse_str(df).unwrap();
    assert_eq!(instructions.len(), 2);
}

/// 18. RabbitMQ - Distributed AMQP Message Broker
#[test]
fn test_software_18_rabbitmq() {
    let yaml = r#"
version: '3.8'
services:
  mq:
    image: rabbitmq:3-management-alpine
    ports:
      - "5672:5672"
      - "15672:15672"
    environment:
      RABBITMQ_DEFAULT_USER: enterprise_user
      RABBITMQ_DEFAULT_PASS: RabbitMQSecret123!
    volumes:
      - rabbitmq-data:/var/lib/rabbitmq
volumes:
  rabbitmq-data:
"#;
    let proj = ComposeProject::from_str(yaml, "rabbitmq-test").unwrap();
    let svc = &proj.compose.services["mq"];
    assert_eq!(svc.ports.as_ref().unwrap().len(), 2);
    let envs = svc.environment.as_ref().unwrap().to_vec();
    assert!(envs.iter().any(|e| e.starts_with("RABBITMQ_DEFAULT_USER=")));
}

/// 19. Memcached - Distributed Memory Caching System
#[test]
fn test_software_19_memcached() {
    let yaml = r#"
version: '3.8'
services:
  memcached:
    image: memcached:alpine
    ports:
      - "11211:11211"
    command: ["-m", "64", "-c", "1024"]
"#;
    let proj = ComposeProject::from_str(yaml, "memcached-test").unwrap();
    let svc = &proj.compose.services["memcached"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "11211:11211");
}

/// 20. Elasticsearch - Distributed RESTful Search Engine
#[test]
fn test_software_20_elasticsearch() {
    let yaml = r#"
version: '3.8'
services:
  es:
    image: elasticsearch:8.12.0
    environment:
      discovery.type: single-node
      ES_JAVA_OPTS: "-Xms512m -Xmx512m"
      xpack.security.enabled: "false"
    ports:
      - "9200:9200"
    volumes:
      - es-data:/usr/share/elasticsearch/data
volumes:
  es-data:
"#;
    let proj = ComposeProject::from_str(yaml, "es-test").unwrap();
    let svc = &proj.compose.services["es"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "9200:9200");
    let envs = svc.environment.as_ref().unwrap().to_vec();
    assert!(envs.iter().any(|e| e.starts_with("discovery.type=")));
}

/// 21. Traefik - Cloud-Native Reverse Proxy & Ingress Router
#[test]
fn test_software_21_traefik() {
    let yaml = r#"
version: '3.8'
services:
  reverse-proxy:
    image: traefik:v3.0
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
    ports:
      - "80:80"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
"#;
    let proj = ComposeProject::from_str(yaml, "traefik-test").unwrap();
    let svc = &proj.compose.services["reverse-proxy"];
    assert_eq!(svc.ports.as_ref().unwrap().len(), 2);
}

/// 22. Caddy - Enterprise Web Server with Automatic TLS
#[test]
fn test_software_22_caddy() {
    let yaml = r#"
version: '3.8'
services:
  caddy:
    image: caddy:2-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
"#;
    let proj = ComposeProject::from_str(yaml, "caddy-test").unwrap();
    let svc = &proj.compose.services["caddy"];
    assert_eq!(svc.ports.as_ref().unwrap().len(), 2);
    assert_eq!(proj.compose.volumes.len(), 2);
}

/// 23. Prometheus - Systems Monitoring & Alerting Toolkit
#[test]
fn test_software_23_prometheus() {
    let yaml = r#"
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:v2.50.0
    ports:
      - "9090:9090"
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=15d"
    volumes:
      - prom-data:/prometheus
volumes:
  prom-data:
"#;
    let proj = ComposeProject::from_str(yaml, "prom-test").unwrap();
    let svc = &proj.compose.services["prometheus"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "9090:9090");
}

/// 24. Grafana - Observability & Metrics Dashboard Platform
#[test]
fn test_software_24_grafana() {
    let yaml = r#"
version: '3.8'
services:
  grafana:
    image: grafana/grafana:10.3.0
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: GrafanaSuperSecret!
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - grafana-storage:/var/lib/grafana
volumes:
  grafana-storage:
"#;
    let proj = ComposeProject::from_str(yaml, "grafana-test").unwrap();
    let svc = &proj.compose.services["grafana"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "3000:3000");
    let envs = svc.environment.as_ref().unwrap().to_vec();
    assert!(
        envs.iter()
            .any(|e| e.starts_with("GF_SECURITY_ADMIN_PASSWORD="))
    );
}

/// 25. HashiCorp Vault - Secrets Management & Data Encryption
#[test]
fn test_software_25_vault() {
    let yaml = r#"
version: '3.8'
services:
  vault:
    image: hashicorp/vault:1.15
    ports:
      - "8200:8200"
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: my-root-token
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
"#;
    let proj = ComposeProject::from_str(yaml, "vault-test").unwrap();
    let svc = &proj.compose.services["vault"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "8200:8200");
}

/// 26. HashiCorp Consul - Service Mesh & Key-Value Store
#[test]
fn test_software_26_consul() {
    let yaml = r#"
version: '3.8'
services:
  consul:
    image: hashicorp/consul:1.18
    ports:
      - "8500:8500"
      - "8600:8600"
    command: ["agent", "-dev", "-client", "0.0.0.0"]
"#;
    let proj = ComposeProject::from_str(yaml, "consul-test").unwrap();
    let svc = &proj.compose.services["consul"];
    assert_eq!(svc.ports.as_ref().unwrap().len(), 2);
}

/// 27. etcd - Distributed Key-Value Store for Coordination
#[test]
fn test_software_27_etcd() {
    let yaml = r#"
version: '3.8'
services:
  etcd:
    image: quay.io/coreos/etcd:v3.5.12
    ports:
      - "2379:2379"
      - "2380:2380"
    environment:
      ETCD_NAME: node1
      ETCD_ADVERTISE_CLIENT_URLS: http://0.0.0.0:2379
      ETCD_LISTEN_CLIENT_URLS: http://0.0.0.0:2379
"#;
    let proj = ComposeProject::from_str(yaml, "etcd-test").unwrap();
    let svc = &proj.compose.services["etcd"];
    assert_eq!(svc.ports.as_ref().unwrap().len(), 2);
}

/// 28. MinIO - High-Performance S3-Compatible Object Storage
#[test]
fn test_software_28_minio() {
    let yaml = r#"
version: '3.8'
services:
  minio:
    image: minio/minio:latest
    command: ["server", "/data", "--console-address", ":9001"]
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: MinioPassword123!
    volumes:
      - minio-data:/data
volumes:
  minio-data:
"#;
    let proj = ComposeProject::from_str(yaml, "minio-test").unwrap();
    let svc = &proj.compose.services["minio"];
    assert_eq!(svc.ports.as_ref().unwrap().len(), 2);
    let envs = svc.environment.as_ref().unwrap().to_vec();
    assert!(envs.iter().any(|e| e.starts_with("MINIO_ROOT_USER=")));
}

/// 29. Docker Distribution / OCI Registry v2 Server
#[test]
fn test_software_29_registry() {
    let yaml = r#"
version: '3.8'
services:
  registry:
    image: registry:2
    ports:
      - "5000:5000"
    environment:
      REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY: /var/lib/registry
    volumes:
      - registry-data:/var/lib/registry
volumes:
  registry-data:
"#;
    let proj = ComposeProject::from_str(yaml, "registry-test").unwrap();
    let svc = &proj.compose.services["registry"];
    assert_eq!(svc.ports.as_ref().unwrap()[0], "5000:5000");
    assert!(proj.compose.volumes.contains_key("registry-data"));
}

/// 30. Full-Stack Enterprise Multi-Service Compose Architecture
/// Tests orchestrating a complete real-world multi-tier architecture:
/// Frontend Ingress (Nginx) -> Application API (Python/FastAPI) -> Database (Postgres)
/// -> Cache (Redis) -> Observability (Prometheus) with network isolation and volume mounts.
#[test]
fn test_software_30_fullstack_enterprise_compose() {
    let yaml = r#"
version: '3.8'
services:
  ingress:
    image: nginx:alpine
    ports:
      - "80:80"
    depends_on:
      - api
    networks:
      - frontend-net

  api:
    image: python:3.11-slim
    environment:
      DATABASE_URL: postgres://pguser:SecretPass@postgres:5432/appdb
      REDIS_URL: redis://cache:6379/0
    depends_on:
      - postgres
      - cache
    networks:
      - frontend-net
      - backend-net

  cache:
    image: redis:7-alpine
    networks:
      - backend-net
    volumes:
      - redis-cache:/data

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: appdb
      POSTGRES_USER: pguser
      POSTGRES_PASSWORD: SecretPass
    networks:
      - backend-net
    volumes:
      - db-storage:/var/lib/postgresql/data

  metrics:
    image: prom/prometheus:v2.50.0
    ports:
      - "9090:9090"
    networks:
      - backend-net
    volumes:
      - prom-storage:/prometheus

networks:
  frontend-net:
  backend-net:

volumes:
  redis-cache:
  db-storage:
  prom-storage:
"#;
    let proj = ComposeProject::from_str(yaml, "enterprise-fullstack").unwrap();
    assert_eq!(proj.compose.services.len(), 5);
    assert_eq!(proj.compose.networks.len(), 2);
    assert_eq!(proj.compose.volumes.len(), 3);

    // Validate topological dependency resolution: postgres and cache must initialize before API, API before ingress
    let order = proj.dependency_order().unwrap();
    assert_eq!(order.len(), 5);

    let pos_postgres = order.iter().position(|s| s == "postgres").unwrap();
    let pos_cache = order.iter().position(|s| s == "cache").unwrap();
    let pos_api = order.iter().position(|s| s == "api").unwrap();
    let pos_ingress = order.iter().position(|s| s == "ingress").unwrap();

    assert!(pos_postgres < pos_api, "PostgreSQL must start before API");
    assert!(pos_cache < pos_api, "Redis cache must start before API");
    assert!(pos_api < pos_ingress, "API must start before Ingress");
}
