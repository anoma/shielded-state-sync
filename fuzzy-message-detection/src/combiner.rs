use alloc::vec::Vec;

/// Combines multiple filtered messages into a smaller collection
/// of messages.
pub struct FilterCombiner;

impl FilterCombiner {
    /// Combines messages whose flags have been filtered ([detected](crate::FmdScheme::detect)) with
    /// different detection keys.
    pub fn combine<T: Eq + Clone>(filtered_messages: &[Vec<T>]) -> Option<Vec<T>> {
        let intersect_all = filtered_messages.iter().cloned().reduce(|acc, filter| {
            let (shortest, largest) = if acc.len() < filter.len() {
                (acc, filter)
            } else {
                (filter, acc)
            };
            let mut intersection = Vec::<T>::with_capacity(shortest.len());
            // Below runs in Ω(|shortest|²) time. An alternative
            // is `Hashset.intersection` from std lib.
            for element in shortest {
                if largest.contains(&element) {
                    intersection.push(element);
                }
            }
            intersection
        });

        if intersect_all.is_some() && intersect_all.clone().unwrap().is_empty() {
            return None;
        }

        intersect_all
    }
}

#[cfg(test)]
mod tests {
    use super::FilterCombiner;

    #[test]
    fn test_filter_combine() -> () {
        // interesects correctly
        let mut combined = FilterCombiner::combine(&[
            vec![0, 1, 2, 3, 4, 5],
            vec![1, 2, 3, 4, 5],
            vec![0, 1, 2, 3],
            vec![2, 3, 4, 5, 6],
        ]);
        assert_eq!(combined.unwrap(), vec![2, 3]);

        // combining disjoint messages yields none
        combined = FilterCombiner::combine(&[vec![0, 1, 2], vec![3, 4]]);
        assert_eq!(true, combined.is_none());

        // combining an empty vector yields none
        combined = FilterCombiner::combine(&[vec![0, 1, 2], vec![]]);
        assert_eq!(true, combined.is_none());

        ()
    }
}
