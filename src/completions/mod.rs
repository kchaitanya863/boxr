//! # Shell Completions & Aliases Subsystem 🐚
//!
//! Generates rich tab completions for **Zsh**, **Bash**, and **Fish**, with dynamic
//! container and image name completions, and installs drop-in Docker wrappers.

pub mod cobra;

use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
}

impl ShellType {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_lowercase().trim() {
            "bash" => Ok(ShellType::Bash),
            "zsh" => Ok(ShellType::Zsh),
            "fish" => Ok(ShellType::Fish),
            other => Err(anyhow!(
                "Unsupported shell '{}', expected bash, zsh, or fish",
                other
            )),
        }
    }

    pub fn detect() -> Self {
        if let Ok(shell_var) = std::env::var("SHELL") {
            if shell_var.contains("zsh") {
                return ShellType::Zsh;
            } else if shell_var.contains("fish") {
                return ShellType::Fish;
            } else if shell_var.contains("bash") {
                return ShellType::Bash;
            }
        }
        ShellType::Zsh
    }
}

pub struct CompletionGenerator;

impl CompletionGenerator {
    pub fn generate(shell: ShellType) -> String {
        match shell {
            ShellType::Bash => Self::generate_bash(),
            ShellType::Zsh => Self::generate_zsh(),
            ShellType::Fish => Self::generate_fish(),
        }
    }

    fn generate_bash() -> String {
        r#"# Bash completion for boxr and docker
_boxr() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="run create start stop restart kill rm pause unpause wait rename update attach exec logs top diff port cp inspect ps images pull push tag rmi history save load import export search build builder compose pod play generate network volume system service daemon stats events info version completion alias unshare spec"

    case "${prev}" in
        volume)
            COMPREPLY=( $(compgen -W "create ls inspect rm prune" -- "${cur}") )
            return 0
            ;;
        network)
            COMPREPLY=( $(compgen -W "create ls inspect rm connect disconnect" -- "${cur}") )
            return 0
            ;;
        compose)
            COMPREPLY=( $(compgen -W "up down ps logs" -- "${cur}") )
            return 0
            ;;
        builder)
            COMPREPLY=( $(compgen -W "prune" -- "${cur}") )
            return 0
            ;;
        service)
            COMPREPLY=( $(compgen -W "install start stop status uninstall" -- "${cur}") )
            return 0
            ;;
        system)
            COMPREPLY=( $(compgen -W "df prune" -- "${cur}") )
            return 0
            ;;
        pod)
            COMPREPLY=( $(compgen -W "create ls rm inspect stop start" -- "${cur}") )
            return 0
            ;;
        play|generate)
            COMPREPLY=( $(compgen -W "kube" -- "${cur}") )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return 0
            ;;
        stop|start|restart|kill|rm|pause|unpause|wait|rename|attach|exec|logs|top|diff|port)
            local containers=$(boxr ps -a -q 2>/dev/null)
            COMPREPLY=( $(compgen -W "${containers}" -- "${cur}") )
            return 0
            ;;
        run|rmi|tag|history|save)
            local images=$(boxr images 2>/dev/null | awk 'NR>1 {print $1":"$2}')
            COMPREPLY=( $(compgen -W "${images}" -- "${cur}") )
            return 0
            ;;
    esac

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "--help --version -i --interactive -t --tty -d --detach --rm --name -e --env -p --publish -v --volume --memory --cpus --pids-limit --rootless --platform --gpus -q --quiet --no-trunc -f --force" -- "${cur}") )
        return 0
    fi

    COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
    return 0
}
complete -F _boxr boxr
complete -F _boxr docker
"#
        .to_string()
    }

    fn generate_zsh() -> String {
        r#"#compdef boxr docker

_boxr() {
    local -a commands
    commands=(
        'run:Run a command in a new container'
        'create:Create a new container without starting it'
        'start:Start one or more stopped containers'
        'stop:Stop one or more running containers'
        'restart:Restart one or more containers'
        'kill:Kill one or more running containers'
        'rm:Remove one or more containers'
        'pause:Pause all processes within one or more containers'
        'unpause:Unpause all processes within one or more containers'
        'wait:Block until one or more containers stop'
        'rename:Rename a container'
        'update:Update configuration of one or more containers'
        'attach:Attach local streams to a running container'
        'exec:Run a command in an existing container'
        'logs:Fetch the logs of a container'
        'top:Display running processes of a container'
        'diff:Inspect changes to files or directories on a container'
        'port:List port mappings for the container'
        'cp:Copy files/folders between a container and local filesystem'
        'inspect:Return low-level information on Boxr objects'
        'ps:List containers'
        'images:List local images'
        'pull:Pull an image from an OCI registry'
        'push:Push an image to an OCI registry'
        'tag:Create a tag TARGET_IMAGE referring to SOURCE_IMAGE'
        'rmi:Remove one or more images'
        'history:Show the history of an image'
        'save:Save one or more images to a tar archive'
        'load:Load an image from a tar archive'
        'import:Import contents from a tarball to create an image'
        'export:Export a container filesystem as a tar archive'
        'search:Search Docker Hub for images'
        'login:Log in to an OCI registry'
        'logout:Log out from an OCI registry'
        'build:Build an image from a Dockerfile'
        'builder:Manage builds and build cache'
        'compose:Define and run multi-container applications'
        'pod:Manage pods of containers'
        'play:Play a pod from Kubernetes YAML'
        'generate:Generate Kubernetes YAML from containers/pods'
        'network:Manage networks'
        'volume:Manage volumes'
        'system:Manage Boxr system (disk usage, prune)'
        'service:Manage Boxr background daemon service'
        'daemon:Run the Boxr background REST API daemon'
        'stats:Display live container resource statistics'
        'events:Get real time events from the server'
        'info:Display system-wide information'
        'version:Show the boxr version information'
        'completion:Generate or install shell completion scripts'
        'alias:Install or print Docker drop-in alias'
        'unshare:Run a command in a new user namespace'
        'spec:Generate a standard OCI runtime specification'
    )

    _arguments -C \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'boxr commands' commands
            ;;
        args)
            case $words[1] in
                stop|start|restart|kill|rm|pause|unpause|wait|rename|attach|exec|logs|top|diff|port)
                    local -a containers
                    containers=($(boxr ps -a -q 2>/dev/null))
                    if [ ${#containers[@]} -gt 0 ]; then
                        _describe -t containers 'containers' containers
                    fi
                    ;;
                run|rmi|tag|history|save)
                    local -a images
                    images=($(boxr images 2>/dev/null | awk 'NR>1 {print $1":"$2}'))
                    if [ ${#images[@]} -gt 0 ]; then
                        _describe -t images 'images' images
                    fi
                    ;;
                volume)
                    local -a vol_cmds
                    vol_cmds=('create:Create volume' 'ls:List volumes' 'inspect:Inspect volume' 'rm:Remove volume' 'prune:Remove unused volumes')
                    _describe -t vol_cmds 'volume commands' vol_cmds
                    ;;
                network)
                    local -a net_cmds
                    net_cmds=('create:Create network' 'ls:List networks' 'inspect:Inspect network' 'rm:Remove network' 'connect:Connect container' 'disconnect:Disconnect container')
                    _describe -t net_cmds 'network commands' net_cmds
                    ;;
                service)
                    local -a srv_cmds
                    srv_cmds=('install:Install autostart service' 'start:Start background daemon' 'stop:Stop background daemon' 'status:Show service status' 'uninstall:Uninstall service')
                    _describe -t srv_cmds 'service commands' srv_cmds
                    ;;
                system)
                    local -a sys_cmds
                    sys_cmds=('df:Show disk usage' 'prune:Remove unused data')
                    _describe -t sys_cmds 'system commands' sys_cmds
                    ;;
                compose)
                    local -a comp_cmds
                    comp_cmds=('up:Create and start containers' 'down:Stop and remove containers' 'ps:List compose containers' 'logs:View compose logs')
                    _describe -t comp_cmds 'compose commands' comp_cmds
                    ;;
                pod)
                    local -a pod_cmds
                    pod_cmds=('create:Create a pod' 'ls:List pods' 'rm:Remove pod' 'inspect:Inspect pod' 'stop:Stop pod' 'start:Start pod')
                    _describe -t pod_cmds 'pod commands' pod_cmds
                    ;;
                play|generate)
                    local -a kube_cmds
                    kube_cmds=('kube:Kubernetes pod YAML format')
                    _describe -t kube_cmds 'kube commands' kube_cmds
                    ;;
                completion)
                    local -a shells
                    shells=('zsh:Zsh completion script' 'bash:Bash completion script' 'fish:Fish completion script')
                    _describe -t shells 'target shell' shells
                    ;;
            esac
            ;;
    esac
}

_boxr "$@"
"#
        .to_string()
    }

    fn generate_fish() -> String {
        r#"# Fish completion for boxr and docker
complete -c boxr -f
complete -c docker -f

# Main subcommands
complete -c boxr -n "__fish_use_subcommand" -a run -d 'Run a command in a new container'
complete -c boxr -n "__fish_use_subcommand" -a create -d 'Create a container without starting it'
complete -c boxr -n "__fish_use_subcommand" -a start -d 'Start stopped containers'
complete -c boxr -n "__fish_use_subcommand" -a stop -d 'Stop running containers'
complete -c boxr -n "__fish_use_subcommand" -a restart -d 'Restart containers'
complete -c boxr -n "__fish_use_subcommand" -a kill -d 'Kill running containers'
complete -c boxr -n "__fish_use_subcommand" -a rm -d 'Remove containers'
complete -c boxr -n "__fish_use_subcommand" -a pause -d 'Pause container processes'
complete -c boxr -n "__fish_use_subcommand" -a unpause -d 'Unpause container processes'
complete -c boxr -n "__fish_use_subcommand" -a wait -d 'Wait for container to stop'
complete -c boxr -n "__fish_use_subcommand" -a rename -d 'Rename a container'
complete -c boxr -n "__fish_use_subcommand" -a update -d 'Update container resources'
complete -c boxr -n "__fish_use_subcommand" -a attach -d 'Attach to container streams'
complete -c boxr -n "__fish_use_subcommand" -a exec -d 'Execute command in container'
complete -c boxr -n "__fish_use_subcommand" -a logs -d 'Fetch container logs'
complete -c boxr -n "__fish_use_subcommand" -a top -d 'Display running processes'
complete -c boxr -n "__fish_use_subcommand" -a diff -d 'Inspect filesystem changes'
complete -c boxr -n "__fish_use_subcommand" -a port -d 'List port mappings'
complete -c boxr -n "__fish_use_subcommand" -a cp -d 'Copy files/folders'
complete -c boxr -n "__fish_use_subcommand" -a inspect -d 'Return low-level information'
complete -c boxr -n "__fish_use_subcommand" -a ps -d 'List containers'
complete -c boxr -n "__fish_use_subcommand" -a images -d 'List local images'
complete -c boxr -n "__fish_use_subcommand" -a pull -d 'Pull an image'
complete -c boxr -n "__fish_use_subcommand" -a push -d 'Push an image'
complete -c boxr -n "__fish_use_subcommand" -a tag -d 'Tag an image'
complete -c boxr -n "__fish_use_subcommand" -a rmi -d 'Remove images'
complete -c boxr -n "__fish_use_subcommand" -a history -d 'Show image history'
complete -c boxr -n "__fish_use_subcommand" -a save -d 'Save image tar'
complete -c boxr -n "__fish_use_subcommand" -a load -d 'Load image tar'
complete -c boxr -n "__fish_use_subcommand" -a import -d 'Import image from tar'
complete -c boxr -n "__fish_use_subcommand" -a export -d 'Export container rootfs'
complete -c boxr -n "__fish_use_subcommand" -a search -d 'Search Docker Hub'
complete -c boxr -n "__fish_use_subcommand" -a login -d 'Login to registry'
complete -c boxr -n "__fish_use_subcommand" -a logout -d 'Logout from registry'
complete -c boxr -n "__fish_use_subcommand" -a build -d 'Build image from Dockerfile'
complete -c boxr -n "__fish_use_subcommand" -a builder -d 'Manage build cache'
complete -c boxr -n "__fish_use_subcommand" -a compose -d 'Manage multi-container app'
complete -c boxr -n "__fish_use_subcommand" -a pod -d 'Manage pods'
complete -c boxr -n "__fish_use_subcommand" -a play -d 'Play Kubernetes YAML'
complete -c boxr -n "__fish_use_subcommand" -a generate -d 'Generate Kubernetes YAML'
complete -c boxr -n "__fish_use_subcommand" -a network -d 'Manage networks'
complete -c boxr -n "__fish_use_subcommand" -a volume -d 'Manage volumes'
complete -c boxr -n "__fish_use_subcommand" -a system -d 'System df and prune'
complete -c boxr -n "__fish_use_subcommand" -a service -d 'Manage daemon service'
complete -c boxr -n "__fish_use_subcommand" -a daemon -d 'Start background daemon'
complete -c boxr -n "__fish_use_subcommand" -a stats -d 'Live container stats'
complete -c boxr -n "__fish_use_subcommand" -a events -d 'Stream container events'
complete -c boxr -n "__fish_use_subcommand" -a info -d 'System information'
complete -c boxr -n "__fish_use_subcommand" -a version -d 'Version information'
complete -c boxr -n "__fish_use_subcommand" -a completion -d 'Shell completions'
complete -c boxr -n "__fish_use_subcommand" -a alias -d 'Docker drop-in alias'
complete -c boxr -n "__fish_use_subcommand" -a unshare -d 'Unshare user namespace'
complete -c boxr -n "__fish_use_subcommand" -a spec -d 'Generate OCI spec'

# Subcommands
complete -c boxr -n "__fish_seen_subcommand_from volume" -a "create ls inspect rm prune"
complete -c boxr -n "__fish_seen_subcommand_from network" -a "create ls inspect rm connect disconnect"
complete -c boxr -n "__fish_seen_subcommand_from service" -a "install start stop status uninstall"
complete -c boxr -n "__fish_seen_subcommand_from system" -a "df prune"
complete -c boxr -n "__fish_seen_subcommand_from compose" -a "up down ps logs"
complete -c boxr -n "__fish_seen_subcommand_from pod" -a "create ls rm inspect stop start"
complete -c boxr -n "__fish_seen_subcommand_from play" -a "kube"
complete -c boxr -n "__fish_seen_subcommand_from generate" -a "kube"
complete -c boxr -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"

# Dynamic container completions
complete -c boxr -n "__fish_seen_subcommand_from stop start restart kill rm pause unpause wait rename attach exec logs top diff port" -a "(boxr ps -a -q 2>/dev/null)"

# Dynamic image completions
complete -c boxr -n "__fish_seen_subcommand_from run rmi tag history save" -a "(boxr images 2>/dev/null | awk 'NR>1 {print \$1\":\"\$2}')"
"#
        .to_string()
    }

    /// Automatically install completion script into the user's shell environment
    pub fn install(shell: ShellType) -> Result<PathBuf> {
        let home = if let Ok(h) = std::env::var("HOME") {
            PathBuf::from(h)
        } else {
            return Err(anyhow!("Could not determine HOME directory"));
        };

        match shell {
            ShellType::Zsh => {
                let zfunc_dir = home.join(".zfunc");
                fs::create_dir_all(&zfunc_dir)?;
                let completion_file = zfunc_dir.join("_boxr");
                fs::write(&completion_file, Self::generate_zsh())?;

                // Check ~/.zshrc
                let zshrc = home.join(".zshrc");
                let mut lines = if zshrc.exists() {
                    fs::read_to_string(&zshrc).unwrap_or_default()
                } else {
                    String::new()
                };

                let setup_snippet = "\n# boxr zsh tab completions\nfpath=(~/.zfunc $fpath)\nautoload -Uz compinit && compinit -u\n";
                if !lines.contains(".zfunc") {
                    lines.push_str(setup_snippet);
                    fs::write(&zshrc, lines)?;
                }

                println!(
                    "✓ Installed Zsh completions to: {}",
                    completion_file.display()
                );
                println!("  Configured fpath in: {}", zshrc.display());
                println!("\nTo activate immediately in your current shell:");
                println!("  fpath=(~/.zfunc $fpath) && autoload -Uz compinit && compinit");
                Ok(completion_file)
            }
            ShellType::Bash => {
                let bash_dir = home.join(".bash_completion.d");
                fs::create_dir_all(&bash_dir)?;
                let completion_file = bash_dir.join("boxr.bash");
                fs::write(&completion_file, Self::generate_bash())?;

                #[cfg(target_os = "macos")]
                let bash_rc_file = {
                    let bp = home.join(".bash_profile");
                    if bp.exists() {
                        bp
                    } else {
                        let prof = home.join(".profile");
                        if prof.exists() {
                            prof
                        } else {
                            home.join(".bash_profile")
                        }
                    }
                };
                #[cfg(not(target_os = "macos"))]
                let bash_rc_file = home.join(".bashrc");

                let mut lines = if bash_rc_file.exists() {
                    fs::read_to_string(&bash_rc_file).unwrap_or_default()
                } else {
                    String::new()
                };

                let source_snippet = "\n# boxr bash completions\n[ -f ~/.bash_completion.d/boxr.bash ] && source ~/.bash_completion.d/boxr.bash\n";
                if !lines.contains("boxr.bash") {
                    lines.push_str(source_snippet);
                    fs::write(&bash_rc_file, lines)?;
                }

                println!(
                    "✓ Installed Bash completions to: {}",
                    completion_file.display()
                );
                println!("\nTo activate immediately in your current shell:");
                println!("  source ~/.bash_completion.d/boxr.bash");
                Ok(completion_file)
            }
            ShellType::Fish => {
                let fish_dir = home.join(".config/fish/completions");
                fs::create_dir_all(&fish_dir)?;
                let completion_file = fish_dir.join("boxr.fish");
                fs::write(&completion_file, Self::generate_fish())?;

                println!(
                    "✓ Installed Fish completions to: {}",
                    completion_file.display()
                );
                Ok(completion_file)
            }
        }
    }

    /// Install Docker drop-in wrapper in ~/.boxr/bin/docker
    pub fn install_docker_wrapper() -> Result<String> {
        let home = boxr_home();
        let bin_dir = home.join("bin");
        fs::create_dir_all(&bin_dir)?;

        let current_exe = std::env::current_exe()?;
        let current_exe_str = current_exe.to_string_lossy();

        let wrapper_script = format!("#!/bin/sh\nexec \"{}\" \"$@\"\n", current_exe_str);

        let wrapper_path = bin_dir.join("docker");
        fs::write(&wrapper_path, wrapper_script)?;

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&wrapper_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&wrapper_path, perms)?;
        }

        Ok(bin_dir.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_completion_generation() {
        let bash = CompletionGenerator::generate(ShellType::Bash);
        assert!(bash.contains("complete -F _boxr boxr"));
        assert!(bash.contains("complete -F _boxr docker"));
        assert!(bash.contains("service"));
        assert!(bash.contains("compose"));

        let zsh = CompletionGenerator::generate(ShellType::Zsh);
        assert!(zsh.contains("#compdef boxr docker"));
        assert!(zsh.contains("service:Manage Boxr background daemon service"));
        assert!(zsh.contains("run:Run a command in a new container"));

        let fish = CompletionGenerator::generate(ShellType::Fish);
        assert!(fish.contains("complete -c boxr"));
        assert!(fish.contains("complete -c docker"));
        assert!(fish.contains("-a run"));
        assert!(fish.contains("-a service"));
    }

    #[test]
    fn test_shell_type_parsing() {
        assert_eq!(ShellType::parse("bash").unwrap(), ShellType::Bash);
        assert_eq!(ShellType::parse("zsh").unwrap(), ShellType::Zsh);
        assert_eq!(ShellType::parse("fish").unwrap(), ShellType::Fish);
        assert!(ShellType::parse("powershell").is_err());
    }
}
