//! Faithful Rust ports of the P4-small legacy JS/Python surfaces.
//! See per-module docs for the JS source each port mirrors.

pub mod forges;

pub use forges::{
    action_summary, azure_devops_adapter, bitbucket_adapter, gitlab_ci_adapter,
    install_preview, mcp_install_config, sarif_upload_command, AzureDevopsAdapter,
    BitbucketAdapter, GitlabCiAdapter,
};
