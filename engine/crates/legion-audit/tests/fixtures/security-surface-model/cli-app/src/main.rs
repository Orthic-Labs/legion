use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    target: String,
}

fn main() {
    let args = Args::parse();
    let token = std::env::var("API_TOKEN").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    println!("{} {} {}", args.target, token.len(), home.len());
}
