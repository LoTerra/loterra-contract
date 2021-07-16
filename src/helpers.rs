pub fn count_match(x: &str, y: &str) -> usize {
    let mut count = 0;
    for i in 0..y.len() {
        if x.chars().nth(i).unwrap() == y.chars().nth(i).unwrap() {
            count += 1;
        }
    }
    count
}
// There is probably some built-in function for this, but this is a simple way to do it
pub fn is_lower_hex(combination: &str, len: u8) -> bool {
    if combination.len() != (len as usize) {
        return false;
    }
    if !combination
        .chars()
        .all(|c| ('a'..='f').contains(&c) || ('0'..='9').contains(&c))
    {
        return false;
    }
    true
}
