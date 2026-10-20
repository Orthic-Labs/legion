// handle performs fallible network I/O and may return transient errors.
fn process(job: Job) -> Result<(), Error> { handle(job) }
