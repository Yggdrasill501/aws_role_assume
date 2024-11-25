"""Module for s3fs credential refresher exceptions."""


class AWSError(Exception):
    """Base exception for AWS-related errors."""


class RoleAssumeError(AWSError):
    """Exception raised when role assumption fails."""


class SigningError(AWSError):
    """Exception raised when request signing fails."""


class CredentialError(AWSError):
    """Exception raised when there are credential-related issues."""
