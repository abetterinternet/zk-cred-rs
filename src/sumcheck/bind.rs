use crate::fields::FieldElement;
use std::ops::Mul;

/// Something indexed by an array of `usize`.
trait Indexable<T>: Clone + std::fmt::Debug {
    /// Retrieve the `T` at the index.
    fn element(&self, index: &[usize]) -> Option<&T>;
}

// Provide implementations of Indexable for different numbers of dimensions. This is a little crude,
// because we'd have to add impls should we ever encounter 4 or more dimensions.

impl<T: std::fmt::Debug + Clone> Indexable<T> for Vec<T> {
    fn element(&self, index: &[usize]) -> Option<&T> {
        self.get(index[0])
    }
}

impl<T: std::fmt::Debug + Clone> Indexable<T> for Vec<Vec<T>> {
    fn element(&self, index: &[usize]) -> Option<&T> {
        self.get(index[0]).and_then(|s| s.get(index[1]))
    }
}

impl<T: std::fmt::Debug + Clone> Indexable<T> for Vec<Vec<Vec<T>>> {
    fn element(&self, index: &[usize]) -> Option<&T> {
        self.get(index[0])
            .and_then(|s| s.get(index[1]))
            .and_then(|s| s.get(index[2]))
    }
}

/// An arbitrary-dimension array of field elements, conforming to the sumcheck array convention in
/// [6.1][1]:
///
/// > The sumcheck array A[i] is implicitly assumed to be defined for all nonnegative integers i,
/// > padding with zeroes as necessary.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1
pub struct SumcheckArray<'a, I, FE> {
    inner: &'a I,
    x: &'a [FE],
    scalar_factor: FE,
}

impl<'a, FE: FieldElement, I: Indexable<FE>> Mul<FE> for SumcheckArray<'a, I, FE> {
    type Output = Self;

    fn mul(mut self, rhs: FE) -> Self::Output {
        self.scalar_factor = rhs;
        self
    }
}

impl<'a, FE: FieldElement, I: Indexable<FE>> SumcheckArray<'a, I, FE> {
    /// Bind an arbitrary dimension array of field elements to a one-dimensional array of field
    /// elements.
    /// This  corresponds to `bindv()` from [6.1][1]. The function `bind()` can be realized by
    /// passing an array of a single element.
    pub fn bind(inner: &'a I, x: &'a [FE]) -> Self {
        Self {
            inner,
            x,
            scalar_factor: FE::ONE,
        }
    }

    /// Get the element at the index.
    pub fn get(&self, index: &[usize]) -> FE {
        self.get_recursive(index, self.x)
    }

    fn get_recursive(&self, index: &[usize], x: &'a [FE]) -> FE {
        if x.is_empty() {
            // Base case. The sumcheck array convention: A[i] is defined for all i, padding with
            // zeroes as necessary. Indexable::element implements multi-dimensional array lookup.
            return *self.inner.element(index).unwrap_or(&FE::ZERO);
        }

        // Per 6.1: B[1] = (1 - x) * A[2 * i] + x * A[2 * i + 1]
        // where B is the bound array and A is the original sumcheck array.
        // Generalizing to a multi-dimensional A:
        //
        //  B[g, l, r, ...] = (1 - x) * A[2 * g, l, r, ...] + x * A[2 * g + 1, l, r, ...]
        //
        // where g, l, r, ... is an index consisting of arbitrarily many elements. We always bind
        // across the first dimension, so regardless of the size of index, we just fix up its 0th
        // element and recurse.
        let mut index = index.to_vec();
        index[0] *= 2;

        let first_term = (FE::ONE - x[0]) * self.get_recursive(index.as_slice(), &x[1..]);

        index[0] += 1;
        let second_term = x[0] * self.get_recursive(index.as_slice(), &x[1..]);

        first_term + second_term
    }
}
