use {std::io, thiserror::Error as ThisError};

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Connection illegal for this process")]
    ConnectionIllegal,
    #[error("Connection already exists")]
    ConnectionAlreadyExists,
    #[error("Connection does not exist")]
    ConnectionDoesNotExit,
    #[error("I/O error")]
    Io(#[from] io::Error),
}