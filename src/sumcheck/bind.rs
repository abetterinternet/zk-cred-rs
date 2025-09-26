use std::ops::Mul;
use zk_cred_longfellow_fields::FieldElement;

/// Something indexed by an array of `usize`.
pub trait Indexable<T>: Clone + std::fmt::Debug {
    /// Retrieve the `T` at the index.
    fn element(&self, index: &[usize]) -> Option<T>;
}

// Provide implementations of Indexable for different numbers of dimensions. This is a little crude,
// because we'd have to add impls should we ever encounter 4 or more dimensions.

impl<T: std::fmt::Debug + Clone> Indexable<T> for Vec<T> {
    fn element(&self, index: &[usize]) -> Option<T> {
        self.get(index[0]).cloned()
    }
}

impl<T: std::fmt::Debug + Clone> Indexable<T> for Vec<Vec<T>> {
    fn element(&self, index: &[usize]) -> Option<T> {
        self.get(index[0]).and_then(|s| s.get(index[1])).cloned()
    }
}

impl<T: std::fmt::Debug + Clone> Indexable<T> for Vec<Vec<Vec<T>>> {
    fn element(&self, index: &[usize]) -> Option<T> {
        self.get(index[0])
            .and_then(|s| s.get(index[1]))
            .and_then(|s| s.get(index[2]))
            .cloned()
    }
}

/// An arbitrary-dimension array of field elements, conforming to the sumcheck array convention in
/// [6.1][1]:
///
/// > The sumcheck array A[i] is implicitly assumed to be defined for all nonnegative integers i,
/// > padding with zeroes as necessary.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1
#[derive(Clone, Debug)]
pub struct SumcheckArray<'a, I, FE> {
    /// The original array of field elements to bind to.
    inner: &'a I,
    /// The elements being bound to the array. Generally described as "x" in the specification.
    binding: Vec<FE>,
    /// A factor by which to scale elements of the matrix.
    scalar_factor: FE,
    /// Whether the last two dimensions of the array should be transposed.
    transpose: bool,
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
    pub fn bind(inner: &'a I, binding: &[FE]) -> Self {
        Self {
            inner,
            binding: binding.to_vec(),
            scalar_factor: FE::ONE,
            transpose: false,
        }
    }

    /// Bind a bound array to a new binding.
    pub fn rebind(&mut self, binding: &[FE]) {
        // bindv(bindv[A, X], Y) is equivalent to bindv(A, X || Y)
        self.binding.extend_from_slice(binding);
    }

    /// Transpose the last two dimensions of the array. This only really makes sense to do if the
    /// array is two-dimensional or has been reduced to two dimensions by binding.
    pub fn transpose(&mut self) {
        self.transpose ^= true
    }

    /// Get the element at the index.
    pub fn get(&self, index: &[usize]) -> FE {
        // Make a copy of the index so we can transpose it and so get_recursive can do arithmetic on
        // it.
        let mut index = index.to_vec();

        if self.transpose {
            let index_len = index.len();
            let last_item = index[index_len - 1];
            index[index_len - 1] = index[index.len() - 2];
            index[index_len - 2] = last_item;
        }
        self.get_recursive(&mut index, &self.binding)
    }

    fn get_recursive(&self, index: &mut [usize], binding: &[FE]) -> FE {
        if binding.is_empty() {
            // Base case. The sumcheck array convention: A[i] is defined for all i, padding with
            // zeroes as necessary. Indexable::element implements multi-dimensional array lookup.
            return self.inner.element(index).unwrap_or(FE::ZERO);
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
        index[0] *= 2;

        let first_term = (FE::ONE - binding[0]) * self.get_recursive(index, &binding[1..]);

        index[0] += 1;
        let second_term = binding[0] * self.get_recursive(index, &binding[1..]);

        first_term + second_term
    }
}

impl<'a, FE: FieldElement, I: Indexable<FE>> Indexable<FE> for SumcheckArray<'a, I, FE> {
    fn element(&self, index: &[usize]) -> Option<FE> {
        Some(self.get(index))
    }
}
