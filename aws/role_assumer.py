"""Module containing the RoleAssumer for aws."""
import os
import requests
import time
import datetime
import hmac
import hashlib
import requests
import logging
from xml.etree import ElementTree as ET
from urllib.parse import quote
from typing import Dict, Optional
from .request_signer import RequestSigner
from .exceptions import (
    RoleAssumeError,
    SigningError,
    CredentialError
)


class RoleAssumer:
    """Handles AWS role assumption."""

    def __init__(
        self,
        role_arn: Optional[str],
        external_id: Optional[str] = None,
        region: str = 'us-east-1',
        session_duration: int = 3600
    ):
        self.role_arn = role_arn
        self.external_id = external_id
        self.region = region
        self.session_duration = session_duration

        # Get AWS credentials from environment
        self.access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        self.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

        if not self.access_key or not self.secret_key:
            raise CredentialError("AWS credentials not found in environment")

        self.signer = RequestSigner(self.access_key, self.secret_key, region)

    def _get_credential_text(self, element: Optional[ET.Element], name: str) -> str:
        """Extract text content from a credential XML element safely.

        :param element: str, XML element to search in
        :param name: str, Name of the credential field
        :return str: The text content of the element
        :raises RoleAssumeError: If element is None or text is missing
        """
        if element is None:
            raise RoleAssumeError(f"Credentials element is None")

        credential = element.find(f'{{https://sts.amazonaws.com/doc/2011-06-15/}}{name}')
        if credential is None:
            raise RoleAssumeError(f"Missing {name} in credentials response")

        if credential.text is None:
            raise RoleAssumeError(f"No text content in {name} element")

        return credential.text

    def assume_role(self):
        """Assume the specified IAM role.

        :raises RoleAssumeError: if role assumption fails.
        :raises SigningError: if request signing fails.
        :raises CredentialError: if AWS credentials are not found.
        :return: Dict[str, str], temporary credentials.
        """
        params = {
            'Action': 'AssumeRole',
            'Version': '2011-06-15',
            'RoleArn': self.role_arn,
            'RoleSessionName': f's3fs-session-{int(time.time())}',
            'DurationSeconds': str(self.session_duration)
        }

        if self.external_id:
            params['ExternalId'] = self.external_id

        try:
            # Sign the request
            headers = self.signer.sign_request(
                'GET',
                f'https://sts.{self.region}.amazonaws.com',
                params
            )

            # Make the request
            response = requests.get(
                f'https://sts.{self.region}.amazonaws.com',
                params=params,
                headers=headers
            )

            if response.status_code == 403:
                raise RoleAssumeError(
                    f"Failed to assume role {self.role_arn}: Access denied"
                )

            response.raise_for_status()

            # Parse XML response
            root = ET.fromstring(response.content)
            if root is None:
                raise RoleAssumeError("Failed to parse XML response")

            creds = root.find('.//{https://sts.amazonaws.com/doc/2011-06-15/}Credentials')
            if creds is None:
                raise RoleAssumeError("No credentials found in response")

            try:
                return {
                    'AccessKeyId': self._get_credential_text(creds, 'AccessKeyId'),
                    'SecretAccessKey': self._get_credential_text(creds, 'SecretAccessKey'),
                    'SessionToken': self._get_credential_text(creds, 'SessionToken'),
                    'Expiration': self._get_credential_text(creds, 'Expiration')
                }
            except RoleAssumeError as e:
                raise RoleAssumeError(f"Invalid credential format: {str(e)}")

        except ET.ParseError as e:
            raise RoleAssumeError(f"Failed to parse XML response: {str(e)}")

