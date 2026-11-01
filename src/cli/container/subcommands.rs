use super::lifecycle::{
    AttachArgs, ExecArgs, KillArgs, LogsArgs, PauseArgs, RestartArgs, StartArgs, StopArgs,
    UnpauseArgs, WaitArgs,
};
use super::ops::*;
use super::run::RunArgs;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
#[command(help_template = crate::cli::PODMAN_GROUP_HELP, subcommand_required = true, arg_required_else_help = false)]
pub struct ContainerSubcommands {
    #[command(subcommand)]
    pub command: ContainerAction,
}

#[derive(Subcommand, Debug)]
pub enum ContainerAction {
    Run(RunArgs),
    Create(RunArgs),
    Start(StartArgs),
    Stop(StopArgs),
    Restart(RestartArgs),
    Kill(KillArgs),
    Rm(RmArgs),
    Pause(PauseArgs),
    Unpause(UnpauseArgs),
    Wait(WaitArgs),
    Exec(ExecArgs),
    Attach(AttachArgs),
    Logs(LogsArgs),
    #[command(aliases = ["ps", "list"])]
    Ls(PsArgs),
    Inspect(InspectArgs),
    #[command(trailing_var_arg = true)]
    Top(TopArgs),
    Port(PortArgs),
    Cp(CpArgs),
    Diff(DiffArgs),
    Prune(ContainerPruneArgs),
    Update(UpdateArgs),
    Export(ExportArgs),
    Rename(RenameArgs),
    Stats(crate::cli::system::StatsArgs),
    Commit(CommitArgs),
    /// Checkpoint a container
    Checkpoint(ContainerCheckpointArgs),
    /// Restore a container from a checkpoint
    Restore(ContainerRestoreArgs),
    /// Clean up container network and storage
    Cleanup(ContainerCleanupArgs),
    /// Clone a container into a new container
    Clone(ContainerCloneArgs),
    /// Initialize a container
    Init(InitArgs),
    /// Run a container using an image label command
    Runlabel(ContainerRunlabelArgs),
    /// Mount a container filesystem
    Mount(MountArgs),
    /// Unmount a container filesystem
    #[command(alias = "umount")]
    Unmount(UnmountArgs),
    /// Return 0 if the container exists, 1 otherwise
    Exists(ContainerExistsArgs),
}
