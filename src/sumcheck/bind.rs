//! Array wrappers implemeniting sumcheck arrays and the `bind` and `bindv` functions from [1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1

use crate::fields::FieldElement;
use std::ops::Mul;

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
        // Make a copy of the index so we can transpose it.
        let mut index = index.to_vec();

        if self.transpose {
            let index_len = index.len();
            let last_item = index[index_len - 1];
            index[index_len - 1] = index[index.len() - 2];
            index[index_len - 2] = last_item;
        }

        // Reverse the binding so that when we recurse, the first element of the binding will be
        // bound to the innermost array.
        let mut binding = self.binding.clone();
        binding.reverse();

        self.get_recursive(&index, &binding)
    }

    fn get_recursive(&self, index: &[usize], binding: &[FE]) -> FE {
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
        let mut index_copy = index.to_vec();

        index_copy[0] *= 2;
        let first_term = (FE::ONE - binding[0]) * self.get_recursive(&index_copy, &binding[1..]);

        index_copy[0] += 1;
        let second_term = binding[0] * self.get_recursive(&index_copy, &binding[1..]);

        first_term + second_term
    }
}

impl<'a, FE: FieldElement, I: Indexable<FE>> Indexable<FE> for SumcheckArray<'a, I, FE> {
    fn element(&self, index: &[usize]) -> Option<FE> {
        Some(self.get(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::fieldp256::FieldP256;
    use std::iter::Iterator;

    /// An iterator over a sumcheck array. Only really works if the underlying array is
    /// one-dimensional.
    struct SumcheckArrayIterator<'a, Indexable, FieldElement> {
        array: &'a SumcheckArray<'a, Indexable, FieldElement>,
        position: usize,
    }

    impl<'a, FE: FieldElement, I: Indexable<FE>> SumcheckArrayIterator<'a, I, FE> {
        fn new(array: &'a SumcheckArray<'a, I, FE>) -> Self {
            Self { array, position: 0 }
        }
    }

    impl<'a, FE: FieldElement, I: Indexable<FE>> Iterator for SumcheckArrayIterator<'a, I, FE> {
        type Item = FE;

        fn next(&mut self) -> Option<Self::Item> {
            let element = self.array.element(&[self.position]);
            self.position += 1;
            element
        }
    }

    fn field_vec<FE: FieldElement>(values: &[u128]) -> Vec<FE> {
        values.into_iter().map(|v| FE::from_u128(*v)).collect()
    }

    #[test]
    fn one_dimension_bind_nothing() {
        let original = field_vec::<FieldP256>(&[0, 1, 2, 3, 4]);

        // Binding with nothing should yield the unmodified array
        let original_array = SumcheckArray::bind(&original, &[]);
        assert_eq!(
            original,
            SumcheckArrayIterator::new(&original_array)
                .take(original.len())
                .collect::<Vec<_>>(),
        );

        // Indices beyond the length of the original array should be 0
        assert_eq!(original_array.get(&[original.len()]), FieldP256::ZERO);
    }

    #[test]
    fn one_dimension_bind_one() {
        let original = field_vec::<FieldP256>(&[0, 1, 2, 3, 4]);

        // Binding to 1 makes the (1 - x) term of bind() go to zero
        let bound_one = SumcheckArray::bind(&original, &[FieldP256::ONE]);
        assert_eq!(
            field_vec::<FieldP256>(&[1, 3, 0, 0, 0]),
            SumcheckArrayIterator::new(&bound_one)
                .take(original.len())
                .collect::<Vec<_>>(),
        );

        // Indices beyond the length of the original array should be 0
        assert_eq!(bound_one.get(&[original.len()]), FieldP256::ZERO);
    }

    #[test]
    fn one_dimension_bind_zero() {
        let original = field_vec::<FieldP256>(&[0, 1, 2, 3, 4]);

        // Binding to 0 makes the x term of bind() go to zero
        let bound_zero = SumcheckArray::bind(&original, &[FieldP256::ZERO]);
        assert_eq!(
            field_vec::<FieldP256>(&[0, 2, 4, 0, 0]),
            SumcheckArrayIterator::new(&bound_zero)
                .take(original.len())
                .collect::<Vec<_>>(),
        );

        // Indices beyond the length of the original array should be 0
        assert_eq!(bound_zero.get(&[original.len()]), FieldP256::ZERO);
    }

    #[test]
    fn bind_sumcheck_array() {
        let original = field_vec::<FieldP256>(&[0, 1, 2, 3, 4]);

        // Binding to Vec<FieldElement> or SumcheckArray<FieldElement> should yield same result
        let array = SumcheckArray::bind(&original, &[]);
        let bound_to_array = SumcheckArray::bind(&array, &[FieldP256::ONE]);

        assert_eq!(
            field_vec::<FieldP256>(&[1, 3, 0, 0, 0]),
            SumcheckArrayIterator::new(&bound_to_array)
                .take(original.len())
                .collect::<Vec<_>>(),
        );
        assert_eq!(bound_to_array.get(&[original.len()]), FieldP256::ZERO);
    }

    #[test]
    fn multidimensional_bind_one() {
        let original = vec![
            field_vec::<FieldP256>(&[0, 5, 10, 15, 20]),
            field_vec::<FieldP256>(&[1, 6, 11, 16, 21]),
            field_vec::<FieldP256>(&[2, 7, 12, 17, 22]),
            field_vec::<FieldP256>(&[3, 8, 13, 18, 23]),
            field_vec::<FieldP256>(&[4, 9, 14, 19, 24]),
        ];

        // Check that we bind across the first dimension only.
        let bound_one = SumcheckArray::bind(&original, &[FieldP256::ONE]);
        // Accessing row 0 of the bound array should access row 1 of the underlying array, but the
        // column access is unaffected.
        assert_eq!(bound_one.get(&[0, 0]), FieldP256::from_u128(1));
        assert_eq!(bound_one.get(&[0, 1]), FieldP256::from_u128(6));
        // Accessing row 1 of the bound array should access row 3 of the underlying array.
        assert_eq!(bound_one.get(&[1, 2]), FieldP256::from_u128(13));
        assert_eq!(bound_one.get(&[1, 4]), FieldP256::from_u128(23));
        // Accessing row 2 of the bound array should access row 5 of the underlying array, going
        // past its limits and yielding zero.
        assert_eq!(bound_one.get(&[2, 2]), FieldP256::ZERO);
    }

    #[test]
    fn one_dimension_bindv() {
        // Bind to multiple field elements, described as bindv in the spec
        let original = field_vec::<FieldP256>(&(0..100).collect::<Vec<_>>());

        let original_array = SumcheckArray::bind(&original, &[]);

        let bound_v = SumcheckArray::bind(
            &original,
            &[FieldP256::from_u128(1), FieldP256::from_u128(2)],
        );

        // Expand bindv(A, [x0, x1])[i] to
        // (1 - x1) * ((1 - x0) * A[4i] + x0 * A[4i + 1])
        //     + x1 * ((1 - x0) * A[4i + 2] + x0 * A[4i + 3])
        // Plugging in x0 = 1, x1 = 2:
        // bind(A, [1, 2])[i] = 2 * A[4i + 3] - A[4i + 1]
        for index in 0..101 {
            assert_eq!(
                bound_v.get(&[index]),
                FieldP256::from_u128(2) * original_array.get(&[4 * index + 3])
                    - original_array.get(&[4 * index + 1]),
                "mismatch at index {index}"
            );
        }
    }

    #[test]
    fn rebind() {
        // Binding to [1, 2] should be the same as binding to [1] and rebinding to [2]
        let original = field_vec::<FieldP256>(&(0..100).collect::<Vec<_>>());

        let bound_v = SumcheckArray::bind(
            &original,
            &[FieldP256::from_u128(1), FieldP256::from_u128(2)],
        );

        let mut rebound = SumcheckArray::bind(&original, &[FieldP256::from_u128(1)]);
        rebound.rebind(&[FieldP256::from_u128(2)]);

        for index in 0..101 {
            assert_eq!(
                bound_v.get(&[index]),
                rebound.get(&[index]),
                "mismatch at index {index}"
            );
        }
    }

    #[test]
    fn transpose_2d() {
        let original = vec![
            field_vec::<FieldP256>(&[0, 5, 10, 15, 20]),
            field_vec::<FieldP256>(&[1, 6, 11, 16, 21]),
            field_vec::<FieldP256>(&[2, 7, 12, 17, 22]),
            field_vec::<FieldP256>(&[3, 8, 13, 18, 23]),
            field_vec::<FieldP256>(&[4, 9, 14, 19, 24]),
        ];

        let mut array = SumcheckArray::<_, FieldP256>::bind(&original, &[]);

        array.transpose();

        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(array.get(&[i, j]), original[j][i]);
            }
        }

        array.transpose();

        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(array.get(&[i, j]), original[i][j]);
            }
        }
    }

    #[test]
    fn transpose_3d() {
        // Transposing a 3d array should only affect the last two dimensions
        let original = vec![vec![
            field_vec::<FieldP256>(&[0, 5, 10, 15, 20]),
            field_vec::<FieldP256>(&[1, 6, 11, 16, 21]),
            field_vec::<FieldP256>(&[2, 7, 12, 17, 22]),
            field_vec::<FieldP256>(&[3, 8, 13, 18, 23]),
            field_vec::<FieldP256>(&[4, 9, 14, 19, 24]),
        ]];

        let mut array = SumcheckArray::<_, FieldP256>::bind(&original, &[]);

        array.transpose();

        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(array.get(&[0, i, j]), original[0][j][i]);
            }
        }

        array.transpose();

        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(array.get(&[0, i, j]), original[0][i][j]);
            }
        }
    }
}
