pub fn html(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
    output
}

pub fn markdown(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.replace(['\r', '\n'], " ").chars() {
        match character {
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' | '#' | '<' | '>' | '&' | '!' | '(' | ')'
            | '{' | '}' => {
                output.push('\\');
                output.push(character);
            }
            _ => output.push(character),
        }
    }
    output
}

/// Render an arbitrary value in a Markdown code span without allowing its
/// backticks to terminate the span.
pub fn markdown_code(value: &str) -> String {
    let value = value.replace(['\r', '\n'], " ");
    let longest_run = value
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let delimiter = "`".repeat(longest_run + 1);
    if value.starts_with(' ')
        || value.ends_with(' ')
        || value.starts_with('`')
        || value.ends_with('`')
    {
        format!("{delimiter} {value} {delimiter}")
    } else {
        format!("{delimiter}{value}{delimiter}")
    }
}
