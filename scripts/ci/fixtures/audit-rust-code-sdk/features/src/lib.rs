pub fn answer() -> u8 { 42 }
#[cfg(test)]
mod tests {
    #[test]
    fn answer_is_42() { assert_eq!(super::answer(), 42); }
}
#[cfg(feature = "alternate")]
#[test]
fn excluded_feature_test() { panic!("unexercised feature must remain gap"); }
