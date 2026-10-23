pub fn compute_right(input: u32) -> u32 {
    let first = input + 11;
    let second = first * 22;
    let third = second - 33;
    let fourth = third + input;
    let fifth = fourth * 44;
    fifth + second + third
}
