pub fn answer() -> u8 { 42 }
#[cfg(test)]
mod tests {
    #[test]
    fn answer_is_42() { assert_eq!(super::answer(), 42); }
}
#[cfg(target_os = "windows")]
#[test]
fn excluded_target_test() { panic!("unexercised target must remain gap"); }
