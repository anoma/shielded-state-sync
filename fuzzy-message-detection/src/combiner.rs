use alloc::vec;

/// Combines multiple filtered messages into a smaller collection
/// of messages.
pub struct FilterCombiner;

impl FilterCombiner {
    /// Combines messages whose flags have been filtered ([detected](crate::MultiFmdScheme::detect)) with
    /// different detection keys.
    pub fn combine<T: Eq + Clone>(filtered_messages: &[vec::Vec<T>]) -> vec::Vec<T> {
        if filtered_messages.is_empty() {
            return vec![];
        }
        let mut result = vec![];
        filtered_messages[0].iter().for_each(|msg| {
            if filtered_messages[1..].iter().all(|list| list.contains(msg)) {
                result.push(msg.clone());
            }
        });
        result
    }
}

#[cfg(test)]
mod tests {
    use super::FilterCombiner;

    #[test]
    fn test_filter_combine() {
        // interesects correctly
        let mut combined = FilterCombiner::combine(&[
            vec![0, 1, 2, 3, 4, 5],
            vec![1, 2, 3, 4, 5],
            vec![0, 1, 2, 3],
            vec![2, 3, 4, 5, 6],
        ]);
        assert_eq!(combined, vec![2, 3]);

        // combining disjoint messages yields empty
        combined = FilterCombiner::combine(&[vec![0, 1, 2], vec![3, 4]]);
        assert!(combined.is_empty());

        // combining an empty vector yields empty
        combined = FilterCombiner::combine(&[vec![0, 1, 2], vec![]]);
        assert!(combined.is_empty());
    }
}
