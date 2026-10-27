# Augnito GCP cloud penetration test — evidence tool

Runs 48 read only test cases against the Augnito Saudi Arabia **UAT**
environment and screenshots every terminal session, so each finding in the
report is backed by an image of the command that produced it.

Companion to `augnito_revalidation_evidence` (AWS). Same output layout, same
screenshot engine, same guard discipline — rewritten for GCP, GKE and Kong.

## Scope

| | |
|---|---|
| Environment | UAT (client confirmed, 27 Oct 2026 — not production) |
| Granted role | `globalreader`, read only (test case 41 shows what it resolves to) |
| Project | `augnito-sa-prod-506104` (number 871952650502) |
| Region | `me-central2` (Dammam) |
| GKE cluster | `augnito-sa-gke` |
| Cloud SQL | `ambient-mysql-prod` |
| Artifact Registry | `augnito` |
| VPC / subnet | `augnito-sa-vpc` / `augnito-sa-gke-subnet` |
| Load balancer | `8.228.202.254` (Kong Gateway on GKE) |
| Endpoints | `beta-sa-apis.augnito.ai`, `beta-sa-apis-ambient.augnito.ai`, `beta-sa-apps.augnito.ai` |
| Application layer | In scope, for those three endpoints only |

Nothing outside this list is ever contacted. The scope is compiled into the
tool and checked before any command runs. The client confirmed on 27 Oct 2026
that `augnito.ai` and every other name under it are **out of scope**, so no
DNS zone is ever dumped whole and no name outside the three is enumerated or
contacted.

## Install

```bash
./setup_kali.sh
```

Then sign in with the account that was granted read only access:

```bash
gcloud auth login
./.venv/bin/python gcp_assessment_evidence.py --check
```

`--check` reports every tool, the active identity, which project reads
succeed, whether the cluster API answers, and whether each endpoint still
resolves into scope. Fix anything it marks `--` before capturing.

## Run

```bash
python3 gcp_assessment_evidence.py                 # all 48 test cases
python3 gcp_assessment_evidence.py --only 2,16,25  # chosen test cases
python3 gcp_assessment_evidence.py --only 1-9      # a range
python3 gcp_assessment_evidence.py --no-scan       # GCP checks only, no nmap or curl
python3 gcp_assessment_evidence.py --no-kubectl    # skip the in cluster test cases
python3 gcp_assessment_evidence.py --no-app-layer  # skip the application layer test cases
python3 gcp_assessment_evidence.py --dry-run       # print every command, run nothing
python3 gcp_assessment_evidence.py --stamp         # caption strip under each image
```

### Routes for the application layer test cases

Test cases 44 to 48 exercise one route per endpoint, `/api/v1` by default.
Run test case 43 first to find out what the gateway actually publishes, then
point 44 to 48 at real routes:

```bash
# one route for all three endpoints
--app-path /v1/transcribe

# a different route per endpoint
--app-path apps=/ --app-path ambient=/v1/ambient --app-path 1=/v1/transcribe

# a default, with one endpoint overridden
--app-path /v1/transcribe --app-path apps=/
```

An endpoint is named by its hostname, by a unique part of it, or by its number
in the scope document. `apis` is inside two of the three names, so it is
refused as ambiguous and the tool prints the numbered list. A route must be a
URL path: anything carrying a shell metacharacter is refused before the run
starts. The resolved mapping is printed at the top of the run, shown by
`--dry-run`, and written into `_README.txt`.

Test case 43 keeps its own word list whatever `--app-path` says, since
`/api/v1` is one of the paths it probes for and rewriting it would corrupt the
discovery.

Choosing an identity, when several are signed in:

```bash
--account you@your-org.com
--configuration augnito-ksa
--impersonate-service-account reader@augnito-sa-prod-506104.iam.gserviceaccount.com
```

## Test cases

| # | Area | Test case |
|---|---|---|
| 1 | Discovery | Project inventory and enabled service attack surface |
| 2 | GKE | Control plane reachable from the internet |
| 3 | GKE | Cluster hardening controls not enabled |
| 4 | GKE | Node pools without shielded VM and metadata protection |
| 5 | GKE | Node service account over privileged or default |
| 6 | GKE | Version currency and automatic upgrade management |
| 7 | GKE | Cluster logging and monitoring coverage |
| 8 | Kubernetes | Authorisation granted to the assessment identity |
| 9 | Kubernetes | RBAC grants cluster administrator rights broadly |
| 10 | Kubernetes | Workloads run with host level privilege |
| 11 | Kubernetes | Service account tokens mounted into every pod |
| 12 | Kubernetes | Secrets inventory and credentials in pod specifications |
| 13 | Kubernetes | Services exposed beyond the cluster |
| 14 | Kubernetes | Network policy coverage between workloads |
| 15 | Kong | Gateway configuration inside the cluster |
| 16 | Cloud SQL | Instance reachable beyond the VPC |
| 17 | Cloud SQL | Connections not required to use TLS |
| 18 | Cloud SQL | Backup, recovery and deletion protection |
| 19 | Cloud SQL | Database flags and account hygiene |
| 20 | Cloud SQL | Encryption at rest uses Google managed keys only |
| 21 | Storage | Buckets open to unauthenticated users |
| 22 | Storage | Data protection settings |
| 23 | Artifact Registry | Repository access control |
| 24 | Artifact Registry | Container images not scanned for known vulnerabilities |
| 25 | Network | Firewall rules permit unrestricted inbound access |
| 26 | Network | Firewall and VPC flow logging not enabled |
| 27 | Network | VPC topology, routes and Cloud NAT configuration |
| 28 | IAM | Primitive roles and external identities |
| 29 | IAM | Service accounts and user managed keys |
| 30 | IAM | Workload Identity bindings between Kubernetes and GCP |
| 31 | IAM | Organisation policy constraints and audit logging |
| 32 | Load balancing | TLS policy and Cloud Armor protection |
| 33 | DNS | Cloud DNS zone configuration and DNSSEC |
| 34 | Logging | Log retention, sinks and alerting |
| 35 | External | Attack surface of the public load balancer |
| 36 | External | Kong admin API and status endpoints exposed |
| 37 | External | TLS configuration of the published endpoints |
| 38 | External | HTTP security headers and methods |
| 39 | Compute | Compute Engine instances and public addresses |
| 40 | Network | VPC peering and private service access to Cloud SQL |
| 41 | IAM | Custom roles, and what `globalreader` resolves to |
| 42 | IAM | Over privilege reported by Google's own IAM analysis |
| 43 | App layer | Routes published by the gateway |
| 44 | App layer | Authentication enforced at the gateway |
| 45 | App layer | HTTP method and verb tampering |
| 46 | App layer | Cross origin resource sharing policy |
| 47 | App layer | Rate limiting and request throttling |
| 48 | App layer | Error handling and information disclosure |

Test cases 44 to 48 default to the route `/api/v1`. Run 43 first, or get the
route list from the client's API documentation, then re-run 44 to 48 with
`--app-path` pointing at real routes — otherwise they only prove how the
gateway answers an unknown path. The two `apis` hosts and the `apps` front end
rarely share a route, so `--app-path` takes a value per endpoint.

Test cases 8 to 15 need the cluster API to answer. If the control plane has no
public endpoint they are skipped with that reason recorded — which is itself
the expected result for a private cluster.

## Output

```
GCP_Assessment_Evidence_<date>/
    _README.txt      what ran, as what identity, what was skipped or refused,
                     and the result of each test case
    _index.csv       every command, exit code, time, image, whether that command
                     was denied, and the test case result
    _Session/
        session -1.png   date, gcloud configuration, active identity
    GKE Control Plane Reachable from the Internet/
        TC-2 -1.png      screenshot
        TC-2 -1.txt      plain text of the same session
        _index.txt       what each screenshot shows
    ...
GCP_Assessment_Evidence_<date>.zip
```

Each test case carries a **result**:

| result | meaning |
|---|---|
| `review` | the check returned output for the analyst to judge |
| `false` | the check returned nothing to assess — an empty `getIamPolicy`, an empty list, or a refusal. Recorded as a false, as the client asked |
| `not run` | the test case was skipped; `_README.txt` says why |

A 403 in an image is not a failed command. It means the granted role was not
given that permission, and it is recorded as a documented limit of the test —
the `permission_denied` column of `_index.csv` marks the exact command, so a
`false` caused by a refusal is distinguishable from one caused by an empty
result.

## How the screenshots are taken

**xterm engine** (default): each session runs in a real xterm window on a
private Xvfb display, captured exactly as it appears. Nothing opens on your
desktop, and your own display is never touched.

**render engine** (fallback): the session runs in a pseudo terminal and the
pyte terminal emulator draws the screen. Used automatically when Xvfb or
xterm is missing.

Either way every command really runs and the image shows its real output.
Nothing is typed into an image afterwards.

## Safety

The guard runs over every command before anything executes, and again on each
screenshot. It refuses:

- any `gcloud` call that is not `list`, `describe`, `get-iam-policy` or
  another read — including one hidden inside `$( )` or backticks;
- any `kubectl` call that is not `get`, `describe` or `auth can-i`;
- `kubectl get secret -o yaml|json|jsonpath`, so a secret value can never
  reach the evidence;
- any shell program that writes, connects out or starts an interpreter;
- output redirection to a file;
- any packet to a host that is not the load balancer IP or one of the three
  published hostnames, checked again at run time by resolving the name — a
  name re-pointed at a third party is never scanned;
- `curl` with a request body, or any method other than GET, HEAD and OPTIONS,
  on a configuration read. The application layer test cases may send a body and
  may use POST, PUT and PATCH against the three endpoints — but never DELETE,
  which is left to manual testing because it can destroy UAT data without the
  tester seeing what went;
- a method taken from a shell variable, so the allowed list cannot be dodged;
- a file upload, at any layer.

A scan may use an address read at run time out of a scoped resource's own
`gcloud describe` record — that is how Cloud SQL's public address and the GKE
control plane endpoint get tested rather than merely reported. Such a command
must name `augnito-sa-gke` or `ambient-mysql-prod` and may not carry a literal
host of its own.

`gcloud container clusters get-credentials` is the one write, and it only
writes a kubeconfig inside the run's own temporary directory. `~/.kube/config`
is never read or modified.

Secret values are never requested. Kubernetes secrets are listed by name, type
and key count; Cloud SQL accounts by name and host.

## Tests

```bash
python3 test_guard.py
```

89 tests, most of them adversarial: writes, command substitution bypasses,
programs invoked by full path, out of scope hosts, secret dumps, DELETE,
methods hidden in shell variables, file uploads and routes carrying shell
metacharacters must all be refused.
