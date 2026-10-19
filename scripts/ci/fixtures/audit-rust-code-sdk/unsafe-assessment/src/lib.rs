pub fn answer() -> u8 { let value = 42u8; unsafe { *std::ptr::addr_of!(value) } }
#[cfg(test)]
mod tests {
    #[test]
    fn answer_is_42() { assert_eq!(super::answer(), 42); }
}
