use core::fmt;

/// Enum that represents all possible errors that can be returned by `Drbg`
/// constructors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrbgError {
    /// Error that is returned when an empty array is received instead of an
    /// array of seed material.
    EmptyArray,
    /// Error that is returned when an element within an array of seed material
    /// is empty.
    EmptyElement(Vec<usize>),
    /// Error that is returned when the selected hash algorithm's digest size
    /// is below 16 bytes.
    DigestTooSmall(usize),
}

impl fmt::Display for DrbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DrbgError::EmptyArray => {
                write!(f, "Array cannot be empty")
            }
            DrbgError::EmptyElement(indices) => {
                if indices.len() == 1 {
                    write!(f, "Array element at index {} is empty", indices[0])
                } else {
                    write!(
                        f,
                        "Array elements at indices {:?} are empty",
                        indices
                    )
                }
            }
            DrbgError::DigestTooSmall(size) => {
                write!(
                    f,
                    "Hash output size {} bytes is below minimum 16 bytes",
                    size
                )
            }
        }
    }
}

impl std::error::Error for DrbgError {}
