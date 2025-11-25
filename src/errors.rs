use core::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrbgError {
    EmptyArray,
    EmptyElement(Vec<usize>),
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
