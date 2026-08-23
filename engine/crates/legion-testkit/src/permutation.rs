pub fn deterministic_permutations<T: Ord + Clone>(values: &[T]) -> Vec<Vec<T>> {
    let mut values = values.to_vec();
    values.sort();
    let mut output = Vec::new();
    permute(&mut values, 0, &mut output);
    output
}

fn permute<T: Clone>(values: &mut [T], index: usize, output: &mut Vec<Vec<T>>) {
    if index == values.len() {
        output.push(values.to_vec());
        return;
    }
    for position in index..values.len() {
        values.swap(index, position);
        permute(values, index + 1, output);
        values.swap(index, position);
    }
}

pub fn completion_orders<T: Ord + Clone>(values: &[T]) -> Vec<Vec<T>> {
    deterministic_permutations(values)
}

pub fn seeded_permutation<T: Ord + Clone>(values: &[T], seed: u64) -> Vec<T> {
    let mut output = values.to_vec();
    let mut state = seed;
    for index in (1..output.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let position = (state % (index as u64 + 1)) as usize;
        output.swap(index, position);
    }
    output
}
