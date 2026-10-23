pub fn widget_footer() -> u32 {
    let left = 40;
    let right = 50;
    let margin = 60;
    left + right + margin
}

pub fn widget_total() -> u32 {
    widget_header() + widget_body() + widget_footer()
}
