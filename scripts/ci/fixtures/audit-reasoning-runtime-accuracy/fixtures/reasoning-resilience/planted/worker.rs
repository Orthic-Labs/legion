// handle performs fallible network I/O and may return transient errors.
fn process(job: Job) { handle(job).expect("job must succeed"); }
