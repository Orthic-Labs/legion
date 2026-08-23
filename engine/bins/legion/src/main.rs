#![forbid(unsafe_code)]
mod cli;
mod commands;
#[tokio::main]
async fn main() {
    let cancellation = tokio_util::sync::CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
        }
    });
    std::process::exit(cli::run_with_cancellation(std::env::args_os().skip(1), cancellation).await);
}
