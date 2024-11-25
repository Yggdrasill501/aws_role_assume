"""Module for s3fs credential refresher exceptions."""


class S3fsCredentialRefresherError(Exception):
    """Base exception class for credential refresher errors."""


class RoleAssumeError(S3fsCredentialRefresherError):
    """Exception raised when role assumption fails."""


class CredentialServiceError(S3fsCredentialRefresherError):
    """Exception raised when credential service communication fails."""


class CredentialFileError(S3fsCredentialRefresherError):
    """Exception raised when there are issues with the credentials file."""


class MountError(S3fsCredentialRefresherError):
    """Exception raised when mounting operations fail."""


class ConfigurationError(S3fsCredentialRefresherError):
    """Exception raised when there are configuration issues."""

