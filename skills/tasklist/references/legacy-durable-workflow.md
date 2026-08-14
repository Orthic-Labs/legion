# Tasklist Durable Workflow Compatibility

Historical Tasklist Markdown validation was retired with its private validator. This public entrypoint preserves same-agent trigger, durable workflow, receipt, & eight-case eval behavior by adapting to current shared typed-packet validator.

Use [durable workflow](durable-workflow.md). Historical Markdown examples remain intentionally retired: they cannot truthfully pass current `legion-authority-dispatch` validation. New durable records use typed packets plus shared-engine receipts.
