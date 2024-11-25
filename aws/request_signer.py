"""Module containing the RequestSigner for aws."""
import os
import time
import datetime
import hmac
import hashlib
import requests
import logging
from typing import Dict, Optional
from urllib.parse import quote
from xml.etree import ElementTree as ET
from .exceptions import (
    RoleAssumeError,
    SigningError,
    CredentialError
)

class RequestSigner:
    """Handles AWS request signing using Signature Version 4."""

    def __init__(self, access_key: str, secret_key: str, region: str) -> None:
        """Initialize the request signer.

        :param access_key: str, AWS access key.
        :param secret_key: str, AWS secret key.
        :param region: str, AWS region.
        return: None, initialize the request signer.
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region

    def sign_request(self, method: str, url: str, params: Dict[str, str], payload: str = '') -> Dict[str, str]:
            """Create AWS Signature Version 4 for request.

            :param method: str, HTTP method.
            :param url: str, URL.
            :param params: Dict[str, str], query parameters.
            :param payload: str, request payload.
            :raise SigningError: if request signing fails.
            :return: Dict[str, str], signed headers.
            """
            try:
                t = datetime.datetime.utcnow()
                amzdate = t.strftime('%Y%m%dT%H%M%SZ')
                datestamp = t.strftime('%Y%m%d')

                # Create canonical request
                canonical_uri = '/'
                canonical_querystring = '&'.join([
                    f"{k}={quote(v)}" for k, v in sorted(params.items())
                ])
                canonical_headers = (
                    f'host:sts.{self.region}.amazonaws.com\n'
                    f'x-amz-date:{amzdate}\n'
                )
                signed_headers = 'host;x-amz-date'
                payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

                canonical_request = (
                    f"{method}\n{canonical_uri}\n{canonical_querystring}\n"
                    f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
                )

                # Create string to sign
                algorithm = 'AWS4-HMAC-SHA256'
                credential_scope = f"{datestamp}/{self.region}/sts/aws4_request"
                string_to_sign = (
                    f"{algorithm}\n{amzdate}\n{credential_scope}\n"
                    f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
                )

                # Calculate signature
                k_date = hmac.new(
                    f"AWS4{self.secret_key}".encode('utf-8'),
                    datestamp.encode('utf-8'),
                    hashlib.sha256
                ).digest()
                k_region = hmac.new(k_date, self.region.encode('utf-8'), hashlib.sha256).digest()
                k_service = hmac.new(k_region, b"sts", hashlib.sha256).digest()
                k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
                signature = hmac.new(
                    k_signing,
                    string_to_sign.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()

                # Create authorization header
                authorization_header = (
                    f"{algorithm} "
                    f"Credential={self.access_key}/{credential_scope}, "
                    f"SignedHeaders={signed_headers}, "
                    f"Signature={signature}"
                )

                return {
                    'Authorization': authorization_header,
                    'x-amz-date': amzdate
                }

            except Exception as e:
                raise SigningError(f"Failed to sign request: {str(e)}")

