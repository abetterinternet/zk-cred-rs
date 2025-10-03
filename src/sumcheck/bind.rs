//! Array wrappers implemeniting sumcheck arrays and the `bind` and `bindv` functions from [1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1

use crate::fields::FieldElement;

/// An array of field elements, possibly multi-dimensional, conforming to the sumcheck array
/// convention of [6.1][1]:
///
/// > The sumcheck array A[i] is implicitly assumed to be defined for all nonnegative integers i,
/// > padding with zeroes as necessary.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-6.1
pub trait SumcheckArray<FieldElement>: Sized {
    /// Retrieve the element at the index.
    fn sumcheck_element(&self, index: &[usize]) -> FieldElement;

    /// Bind an arbitrary dimension array of field elements to a one-dimensional array of field
    /// elements.
    ///
    /// This corresponds to `bindv()` from [6.1][1]. The function `bind()` can be realized by
    /// passing an array of a single element.
    // TODO: provide in-place version?
    fn bind(&self, binding: &[FieldElement]) -> Result<Self, anyhow::Error>;

    /// Multiply each element in the array by the scalar.
    // TODO: provide in-place version?
    fn scale(&self, scalar: FieldElement) -> Self;

    /// Transpose the last two dimensions of the array. This only really makes sense to do if the
    /// array is two-dimensional or has been reduced to two dimensions by binding and if it is a
    /// rectangular array.
    // TODO: provide in-place version?
    fn transpose(&self) -> Self;
}

impl<FE: FieldElement> SumcheckArray<FE> for Vec<FE> {
    fn sumcheck_element(&self, index: &[usize]) -> FE {
        *self.get(index[0]).unwrap_or(&FE::ZERO)
    }

    fn bind(&self, binding: &[FE]) -> Result<Self, anyhow::Error> {
        let mut bound = self.clone();
        for binding_element in binding {
            for index in 0..self.len() {
                // B[i] = (1 - x) * A[2 * i] + x * A[2 * i + 1]
                bound[index] = (FE::ONE - binding_element) * bound.sumcheck_element(&[2 * index])
                    + *binding_element * bound.sumcheck_element(&[2 * index + 1])
            }
        }

        Ok(bound)
    }

    fn scale(&self, scalar: FE) -> Self {
        self.iter().map(|element| scalar * element).collect()
    }

    fn transpose(&self) -> Self {
        // no-op: can't transpose a 1D array
        self.clone()
    }
}

impl<FE: FieldElement> SumcheckArray<FE> for Vec<Vec<FE>> {
    fn sumcheck_element(&self, index: &[usize]) -> FE {
        self.get(index[0])
            .and_then(|s| s.get(index[1]))
            .cloned()
            .unwrap_or(FE::ZERO)
    }

    fn bind(&self, binding: &[FE]) -> Result<Self, anyhow::Error> {
        let mut bound = self.clone();
        for binding_element in binding {
            for index in 0..self.len() {
                // First term: (1 - x) * A[2 * i]
                // Grab the 2i-th row, scale its elements by 1 - x
                let first_term: Vec<_> = bound
                    .get(2 * index)
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|element| (FE::ONE - binding_element) * element)
                    .collect();

                // Second term: x * A[2 * i + 1]
                // Grab the (2i + 1)th row, scale its elements by x
                let second_term: Vec<_> = bound
                    .get(2 * index + 1)
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|element| *binding_element * element)
                    .collect();

                bound[index] = first_term.elementwise_sum(&second_term)?;
            }
        }

        // Trim empty vecs from the end of bound
        Ok(bound.into_iter().filter(|vec| !vec.is_empty()).collect())
    }

    fn scale(&self, scalar: FE) -> Self {
        self.iter().map(|row| row.scale(scalar)).collect()
    }

    fn transpose(&self) -> Self {
        let mut transposed = vec![vec![FE::ZERO; self.len()]; self[0].len()];

        for i in 0..self.len() {
            #[allow(clippy::needless_range_loop)]
            for j in 0..self[i].len() {
                transposed[j][i] = self.sumcheck_element(&[i, j])
            }
        }

        transposed
    }
}

impl<FE: FieldElement> SumcheckArray<FE> for Vec<Vec<Vec<FE>>> {
    fn sumcheck_element(&self, index: &[usize]) -> FE {
        self.get(index[0])
            .and_then(|s| s.get(index[1]))
            .and_then(|s| s.get(index[2]))
            .cloned()
            .unwrap_or(FE::ZERO)
    }

    fn bind(&self, binding: &[FE]) -> Result<Self, anyhow::Error> {
        let mut bound = self.clone();
        for binding_element in binding {
            for index in 0..self.len() {
                // First term: (1 - x) * A[2 * i]
                // Grab the 2i-th "row", scale its elements by 1 - x
                let first_term: Vec<_> = bound
                    .get(2 * index)
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|element| (FE::ONE - binding_element) * element)
                            .collect::<Vec<_>>()
                    })
                    .collect();

                // Second term: x * A[2 * i + 1]
                // Grab the (2i + 1)th "row", scale its elements by x
                let second_term: Vec<_> = bound
                    .get(2 * index + 1)
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|element| *binding_element * element)
                            .collect::<Vec<_>>()
                    })
                    .collect();

                bound[index] = first_term.elementwise_sum(&second_term)?;
            }
        }

        Ok(bound.into_iter().filter(|vec| !vec.is_empty()).collect())
    }

    fn scale(&self, scalar: FE) -> Self {
        self.iter().map(|array| array.scale(scalar)).collect()
    }

    fn transpose(&self) -> Self {
        self.iter().map(Vec::transpose).collect()
    }
}

/// Something composed of elements that can be summed.
///
/// The more obvious thing would be to use `std::ops::Add` but:
///
///  - We want this to be fallible so that summing two vectors can fail if they
///    are of unequal length
///  - We can't implement `Add` on `Vec` in this crate
pub trait ElementwiseSum: Sized {
    /// Sum with another instance.
    fn elementwise_sum(&self, rhs: &Self) -> Result<Self, anyhow::Error>;
}

impl<T: ElementwiseSum> ElementwiseSum for Vec<T> {
    fn elementwise_sum(&self, rhs: &Self) -> Result<Self, anyhow::Error> {
        self.iter()
            .zip(rhs.iter())
            .map(|(lhs, rhs)| lhs.elementwise_sum(rhs))
            .collect()
    }
}

impl<FE: FieldElement> ElementwiseSum for FE {
    fn elementwise_sum(&self, rhs: &Self) -> Result<Self, anyhow::Error> {
        Ok(*self + *rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::fieldp256::FieldP256;
    use std::iter::Iterator;

    fn field_vec<FE: FieldElement>(values: &[u128]) -> Vec<FE> {
        values.into_iter().map(|v| FE::from_u128(*v)).collect()
    }

    #[test]
    fn one_dimension_bind_nothing() {
        let original = field_vec::<FieldP256>(&[0, 1, 2, 3, 4]);
        let bound = original.bind(&[]).unwrap();

        assert_eq!(original, bound);

        // Indices beyond the length of the original array should be 0
        assert_eq!(
            original.sumcheck_element(&[original.len()]),
            FieldP256::ZERO
        );
    }

    #[test]
    fn one_dimension_bind_one() {
        let original = field_vec::<FieldP256>(&[0, 1, 2, 3, 4]);
        let bound = original.bind(&[FieldP256::ONE]).unwrap();

        assert_eq!(field_vec::<FieldP256>(&[1, 3, 0, 0, 0]), bound);

        // Indices beyond the length of the original array should be 0
        assert_eq!(bound.sumcheck_element(&[original.len()]), FieldP256::ZERO);
    }

    #[test]
    fn one_dimension_bind_zero() {
        let original = field_vec::<FieldP256>(&[0, 1, 2, 3, 4]);
        let bound = original.bind(&[FieldP256::ZERO]).unwrap();

        assert_eq!(field_vec::<FieldP256>(&[0, 2, 4, 0, 0]), bound);

        // Indices beyond the length of the original array should be 0
        assert_eq!(bound.sumcheck_element(&[original.len()]), FieldP256::ZERO);
    }

    #[test]
    fn one_dimension_bind_five() {
        let original = field_vec::<FieldP256>(&(0..100).collect::<Vec<_>>());

        // Bind to some value besides zero or one so that both terms of
        //   B[i] = (1 - x) * A[2 * i] + x * A[2 * i + 1]
        // will be nonzero
        // Noting that in our original array, A[i] = i and plugging in x = 5:
        // B[i] = (1 - 5) * 2i + 5 * (2i + 1)
        // B[i] = 5 * (2i + 1) - 4 * (2i)
        // Keep the two terms separate so we can see if either 2i or 2i + 1 exceeds the size of the
        // original array and yield zeroes appropriately
        let bound = original.bind(&[FieldP256::from(5)]).unwrap();
        assert_eq!(
            field_vec::<FieldP256>(
                &(0..100)
                    .map(|i| {
                        let first_term = if 2 * i >= original.len() {
                            0
                        } else {
                            4 * 2 * i
                        };
                        let second_term = if 2 * i + 1 >= original.len() {
                            0
                        } else {
                            5 * (2 * i + 1)
                        };

                        (second_term - first_term) as u128
                    })
                    .collect::<Vec<_>>()
            ),
            bound,
        );
    }

    #[test]
    fn one_dimension_bindv() {
        // Bind to multiple field elements, described as bindv in the spec
        let original = field_vec::<FieldP256>(&(0..100).collect::<Vec<_>>());
        let bound = original
            .bind(&[FieldP256::from_u128(1), FieldP256::from_u128(2)])
            .unwrap();

        // Expand bindv(A, [x0, x1])[i] to
        // (1 - x1) * ((1 - x0) * A[4i] + x0 * A[4i + 1])
        //     + x1 * ((1 - x0) * A[4i + 2] + x0 * A[4i + 3])
        // Plugging in x0 = 1, x1 = 2:
        // bind(A, [1, 2])[i] = 2 * A[4i + 3] - A[4i + 1]
        for index in 0..100 {
            assert_eq!(
                bound[index],
                FieldP256::from_u128(2) * original.sumcheck_element(&[4 * index + 3])
                    - original.sumcheck_element(&[4 * index + 1]),
                "mismatch at index {index}"
            );
        }
    }

    #[test]
    fn two_dimension_bind_one() {
        let original = vec![
            field_vec::<FieldP256>(&[0, 5, 10, 15, 20]),
            field_vec::<FieldP256>(&[1, 6, 11, 16, 21]),
            field_vec::<FieldP256>(&[2, 7, 12, 17, 22]),
            field_vec::<FieldP256>(&[3, 8, 13, 18, 23]),
            field_vec::<FieldP256>(&[4, 9, 14, 19, 24]),
        ];

        let bound = original.bind(&[FieldP256::ONE]).unwrap();

        // Accessing row 0 of the bound array should access row 1 of the underlying array, but the
        // column access is unaffected.
        assert_eq!(bound[0][0], FieldP256::from_u128(1));
        assert_eq!(bound[0][1], FieldP256::from_u128(6));
        // Accessing row 1 of the bound array should access row 3 of the underlying array.
        assert_eq!(bound[1][2], FieldP256::from_u128(13));
        assert_eq!(bound[1][4], FieldP256::from_u128(23));
        // Accessing row 2 of the bound array should access row 5 of the underlying array, going
        // past its limits and yielding zero.
        assert_eq!(bound.sumcheck_element(&[2, 2]), FieldP256::ZERO);
    }

    #[test]
    fn two_dimension_bindv() {
        let original = vec![
            field_vec::<FieldP256>(&[0; 5]),
            field_vec(&[1; 5]),
            field_vec(&[2; 5]),
            field_vec(&[3; 5]),
            field_vec(&[4; 5]),
            field_vec(&[5; 5]),
            field_vec(&[6; 5]),
            field_vec(&[7; 5]),
            field_vec(&[8; 5]),
            field_vec(&[9; 5]),
            field_vec(&[10; 5]),
            field_vec(&[11; 5]),
            field_vec(&[12; 5]),
            field_vec(&[13; 5]),
            field_vec(&[14; 5]),
        ];

        let bound = original
            .bind(&[FieldP256::ONE, FieldP256::from_u128(2)])
            .unwrap();

        // Expand bindv(A, [x0, x1])[i] to
        // (1 - x1) * ((1 - x0) * A[4i] + x0 * A[4i + 1])
        //     + x1 * ((1 - x0) * A[4i + 2] + x0 * A[4i + 3])
        // Plugging in x0 = 1, x1 = 2:
        // bind(A, [1, 2])[i] = 2 * A[4i + 3] - A[4i + 1]
        // Row 0 of the bound array should be 2 * row 3 - row 1 (elementwise)
        for element in &bound[0] {
            assert_eq!(*element, FieldP256::from(5));
        }

        // Row 1 of the bound array should be 2 * row 7 - row 5 (elementwise)
        for element in &bound[1] {
            assert_eq!(*element, FieldP256::from(9));
        }

        // Row 2 of the bound array should be 2 * row 11 - row 9 (elementwise)
        for element in &bound[2] {
            assert_eq!(*element, FieldP256::from(13));
        }

        // All other values in the bound array should be 0, and thus the vec should be of length 3
        assert_eq!(bound.len(), 3);

        for i in 3..original.len() {
            for j in 0..original[i].len() {
                assert_eq!(bound.sumcheck_element(&[i, j]), FieldP256::ZERO);
            }
        }
    }

    #[test]
    fn three_dimension_bind_one() {
        let original = vec![
            vec![field_vec(&[0; 5]); 2],
            vec![field_vec(&[1; 5]); 2],
            vec![field_vec(&[2; 5]); 2],
            vec![field_vec(&[3; 5]); 2],
            vec![field_vec(&[4; 5]); 2],
        ];

        let bound = original.bind(&[FieldP256::ONE]).unwrap();

        // "Row" 0 (which is an array) should be row 1
        assert_eq!(bound[0], vec![field_vec(&[1; 5]); 2]);

        // "Row" 1 should be row 3
        assert_eq!(bound[1], vec![field_vec(&[3; 5]); 2]);

        // All other values should be 0
        assert_eq!(bound.len(), 2);

        for i in 2..original.len() {
            for j in 0..original[i].len() {
                for k in 0..original[i][j].len() {
                    assert_eq!(bound.sumcheck_element(&[i, j, k]), FieldP256::ZERO);
                }
            }
        }
    }

    #[test]
    fn three_dimension_bindv() {
        let original = vec![
            vec![field_vec(&[0; 5]); 2],
            vec![field_vec(&[1; 5]); 2],
            vec![field_vec(&[2; 5]); 2],
            vec![field_vec(&[3; 5]); 2],
            vec![field_vec(&[4; 5]); 2],
            vec![field_vec(&[5; 5]); 2],
            vec![field_vec(&[6; 5]); 2],
            vec![field_vec(&[7; 5]); 2],
            vec![field_vec(&[8; 5]); 2],
            vec![field_vec(&[9; 5]); 2],
            vec![field_vec(&[10; 5]); 2],
            vec![field_vec(&[11; 5]); 2],
            vec![field_vec(&[12; 5]); 2],
            vec![field_vec(&[13; 5]); 2],
            vec![field_vec(&[14; 5]); 2],
        ];

        let bound = original
            .bind(&[FieldP256::ONE, FieldP256::from_u128(2)])
            .unwrap();

        // "Row" 0 (which is an array) should be 2 * row 3 - row 1 (elementwise)
        assert_eq!(bound[0], vec![field_vec(&[5; 5]); 2]);

        // "Row" 1 should be 2 * row 7 - row 5 (elementwise)
        assert_eq!(bound[1], vec![field_vec(&[9; 5]); 2]);

        // "Row" 2 should be 2 * row 11 - row 9 (elementwise)
        assert_eq!(bound[2], vec![field_vec(&[13; 5]); 2]);

        // All other values should be 0
        assert_eq!(bound.len(), 3);

        for i in 3..original.len() {
            for j in 0..original[i].len() {
                for k in 0..original[i][j].len() {
                    assert_eq!(bound.sumcheck_element(&[i, j, k]), FieldP256::ZERO);
                }
            }
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

        let transposed = original.transpose();

        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(transposed[i][j], original[j][i]);
            }
        }

        let transposed = transposed.transpose();

        for i in 0..original.len() {
            for j in 0..original[i].len() {
                assert_eq!(transposed[i][j], original[i][j]);
            }
        }

        let bound_array = original
            .bind(&[FieldP256::from_u128(2), FieldP256::from_u128(3)])
            .unwrap();
        let transposed_bound_array = bound_array.transpose();

        println!("bound array {bound_array:#?}\ntransposed {transposed_bound_array:#?}");

        for i in 0..original.len() {
            for j in 0..original[i].len() {
                assert_eq!(
                    bound_array.sumcheck_element(&[i, j]),
                    transposed_bound_array.sumcheck_element(&[j, i])
                );
            }
        }

        let transposed_bound_array = transposed_bound_array.transpose();

        for i in 0..original.len() {
            for j in 0..original[i].len() {
                assert_eq!(
                    bound_array.sumcheck_element(&[i, j]),
                    transposed_bound_array.sumcheck_element(&[i, j])
                );
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

        let transposed = original.transpose();

        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(transposed[0][i][j], original[0][j][i]);
            }
        }

        let transposed = transposed.transpose();

        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(transposed[0][i][j], original[0][i][j]);
            }
        }
    }

    #[test]
    fn scalar_mul_1d() {
        let original = field_vec::<FieldP256>(&[1, 2, 3, 4, 5]);

        let scaled = original.scale(FieldP256::from_u128(2));
        assert_eq!(scaled, field_vec(&[2, 4, 6, 8, 10]));

        let scaled_again = scaled.scale(FieldP256::from_u128(3));
        assert_eq!(scaled_again, field_vec(&[6, 12, 18, 24, 30]));
    }

    #[test]
    fn scalar_mul_2d() {
        let original = vec![
            field_vec::<FieldP256>(&[1, 2, 3, 4, 5]),
            field_vec(&[1, 2, 3, 4, 5]),
        ];

        let scaled = original.scale(FieldP256::from_u128(2));
        assert_eq!(
            scaled,
            vec![field_vec(&[2, 4, 6, 8, 10]), field_vec(&[2, 4, 6, 8, 10])]
        );

        let scaled_again = scaled.scale(FieldP256::from_u128(3));
        assert_eq!(
            scaled_again,
            vec![
                field_vec(&[6, 12, 18, 24, 30]),
                field_vec(&[6, 12, 18, 24, 30])
            ]
        );
    }

    #[test]
    fn scalar_mul_3d() {
        let original = vec![
            vec![field_vec::<FieldP256>(&[0; 5]); 2],
            vec![field_vec(&[1; 5]); 2],
        ];

        let scaled = original.scale(FieldP256::from_u128(2));
        assert_eq!(
            scaled,
            vec![
                vec![field_vec::<FieldP256>(&[0; 5]); 2],
                vec![field_vec(&[2; 5]); 2],
            ],
        );

        let scaled_again = scaled.scale(FieldP256::from_u128(3));
        assert_eq!(
            scaled_again,
            vec![
                vec![field_vec::<FieldP256>(&[0; 5]); 2],
                vec![field_vec(&[6; 5]); 2],
            ],
        );
    }
}
