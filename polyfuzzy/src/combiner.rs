use crate::{multifmd2::MultiFmd2, polyfuzzy::Polyfuzzy};

/// How exactly tests are combined might depend on
/// specifics of the application. This trait is
/// used primarily for benchmark purposes.
pub trait CombineTests {
    type TestResult;
    fn combine(&self, results: &[Self::TestResult]) -> bool;
}

macro_rules! combine_test_impl {
        ($($t:ty)*) => ($(
            impl CombineTests for $t {
                type TestResult = bool;

                fn combine(&self, results: &[Self::TestResult]) -> bool {
                    for result in results {
                        if *result != true {
                            return false;
                        }
                    }
                    true
                }
            }
        )*)
    }

combine_test_impl! {MultiFmd2 Polyfuzzy}
