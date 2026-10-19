pub fn answer() -> u8 { return 42; }
#[cfg(test)]
mod tests {
    #[test]
    fn answer_is_42() { assert_eq!(super::answer(), 42); }
}
