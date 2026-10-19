pub fn answer() -> u8 {
    let mut values = smallvec::SmallVec::<[u8; 4]>::new();
    values.push(42);
    values[0]
}
#[cfg(test)]
mod tests {
    #[test]
    fn answer_is_42() { assert_eq!(super::answer(), 42); }
}
