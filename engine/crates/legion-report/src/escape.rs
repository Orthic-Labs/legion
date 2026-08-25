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
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' | '#' => {
                output.push('\\');
                output.push(character);
            }
            _ => output.push(character),
        }
    }
    output
}
