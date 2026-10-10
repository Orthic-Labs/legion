#![forbid(unsafe_code)]
mod apple_mcp;
mod cli;
mod commands;
/// The command future is large (every subcommand's state lives in it), and
/// Windows gives the main thread a 1 MiB stack; `legion apple catalog`
/// overflowed it in debug builds. Run the CLI on a thread sized for it.
const CLI_STACK_BYTES: usize = 16 * 1024 * 1024;

fn main() {
    let code = std::thread::Builder::new()
        .name("legion-cli".into())
        .stack_size(CLI_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(CLI_STACK_BYTES)
                .build()
                .expect("tokio runtime")
                .block_on(run())
        })
        .expect("spawn legion-cli thread")
        .join()
        .unwrap_or(1);
    std::process::exit(code);
}

async fn run() -> i32 {
    let cancellation = tokio_util::sync::CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancellation.cancel();
        }
    });
    cli::run_with_cancellation(std::env::args_os().skip(1), cancellation).await
}
