# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""GDC-H support.
"""

import json

from six.moves import http_client

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions
from google.oauth2 import _client


class Credentials(credentials.Credentials):
    """Credentials for GCD-H.
    """

    def __init__(self, ca_cert_path, cert_path, key_path, k8s_token_endpoint, ais_token_endpoint):
        """
        Args:
            ca_cert_path (str): CA cert path for k8s calls
            cert_path (str): Certificate path for k8s calls
            key_path (str): Key path for k8s calls
            k8s_token_endpoint (str): k8s token endpoint url
            ais_token_endpoint (str): AIS token endpoint url
        Raises:
            ValueError: If the provided API key is not a non-empty string.
        """
        self.ca_cert_path = ca_cert_path
        self.cert_path = cert_path
        self.key_path = key_path
        self.k8s_token_endpoint = k8s_token_endpoint
        self.ais_token_endpoint = ais_token_endpoint
        super(Credentials, self).__init__()

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        # mTLS connection to k8s token endpoint to get a k8s token.
        response = request(method="POST", 
            url=self.k8s_token_endpoint,
            headers={"Content-Type": "application/json"},
            cert=(self.cert_path, self.key_path),
            verify=self.ca_cert_path)

        response_body = (
            response.data.decode("utf-8")
            if hasattr(response.data, "decode")
            else response.data
        )
        response_data = json.loads(response_body)

        if response.status == http_client.OK:
            k8s_token = response_data.get("status").get("token")
            print("received k8s token: {}".format(k8s_token))
        else:
            print("failed to fetch k8s token: {}".format(response_body))
            raise exceptions.RefreshError("failed to fetch k8s token")

        # send a request to AIS token point with the k8s token
        