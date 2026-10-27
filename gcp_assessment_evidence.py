#!/usr/bin/env python3
"""
Augnito GCP cloud penetration test evidence

Runs the read only test cases for the Augnito Saudi Arabia UAT
environment (project augnito-sa-prod-506104, region me-central2) and
screenshots every terminal session. The output folder has the same layout
as the AWS revalidation evidence pack:

    GCP_Assessment_Evidence_<date>/
        _README.txt                 summary of the run
        _index.csv                  every command, exit code, time, image
        _Session/session -1.png     date, gcloud configuration, active identity
        GKE Control Plane Exposed to the Internet/
            TC-1 -1.png             screenshot
            TC-1 -1.txt             plain text of the same session
            _index.txt              what each screenshot shows
        ...

How the screenshots are taken
    xterm engine (default): each session runs in a real xterm window on a
    private virtual display (Xvfb), and the window is captured exactly as
    it appears. Nothing opens on your desktop.
    render engine (fallback): the session runs in a pseudo terminal and the
    pyte terminal emulator draws the screen. Used automatically when Xvfb
    or xterm is missing.
    Either way every command really runs, and the image shows its real
    output. Nothing is typed into the image afterwards.

Safety
    GCP: list, describe and get-iam-policy calls only. Every command is
    checked before anything runs, and the run stops if the credentials
    resolve to any project other than augnito-sa-prod-506104.
    Kubernetes: get, describe and auth can-i only, through a kubeconfig
    private to this run. Your own ~/.kube/config is never touched.
    Network tests (nmap TCP connect scans, curl GET/HEAD/OPTIONS requests)
    only go to the load balancer IP and the three published hostnames, and
    only after the tool confirms at run time that each hostname still
    resolves to an in scope address.
    Secret values are never printed: Kubernetes secrets are listed by name,
    type and key count only, and Cloud SQL users by name and host only.

Usage
    python3 gcp_assessment_evidence.py --check        check tools and access
    python3 gcp_assessment_evidence.py                capture every test case
    python3 gcp_assessment_evidence.py --only 1-9     chosen test cases
    python3 gcp_assessment_evidence.py --no-scan      GCP checks only, no nmap or curl
    python3 gcp_assessment_evidence.py --no-kubectl   skip the in cluster test cases
    python3 gcp_assessment_evidence.py --dry-run      print every command, run nothing
"""

import argparse
import csv
import datetime as dt
import fcntl
import getpass
import json
import os
import pty
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
import zipfile

VERSION = "1.0"

# ---------------------------------------------------------------------------
# Scope (client scope document, Saudi Arabia UAT environment)
# ---------------------------------------------------------------------------
PROJECT = "augnito-sa-prod-506104"
PROJECT_NUMBER = "871952650502"
REGION = "me-central2"
ZONES = ["me-central2-a", "me-central2-b", "me-central2-c"]

CLUSTER = "augnito-sa-gke"
SQL_INSTANCE = "ambient-mysql-prod"
AR_REPO = "augnito"
VPC = "augnito-sa-vpc"
SUBNET = "augnito-sa-gke-subnet"

LB_IP = "8.228.202.254"
# Only these three names are in scope. The client confirmed that augnito.ai and
# every other name under it are out of scope, so nothing enumerates or contacts
# a name that is not on this list.
HOSTS = ["beta-sa-apis.augnito.ai", "beta-sa-apis-ambient.augnito.ai", "beta-sa-apps.augnito.ai"]
# Application layer testing is in scope for these three endpoints. The client
# confirmed this is UAT, not production.
ENVIRONMENT = "UAT"
# The read only grant the client issued.
GRANTED_ROLE = "globalreader"

# Everything that may receive nmap or curl. A hostname is contacted only after
# the tool resolves it at run time and finds an in scope address behind it, so
# a name that has been re-pointed at a third party is never scanned.
SCAN_TARGETS = dict([(LB_IP, "public load balancer (Kong Gateway on GKE)")] +
                    [(h, "published endpoint, must resolve to %s" % LB_IP) for h in HOSTS])
IN_SCOPE_IPS = {LB_IP}

P = "--project " + PROJECT
GCLOUD_ERR = (0, 1, 2)   # a 403 or NOT_FOUND exits 1 and is evidence in its own right
KUBE_ERR = (0, 1)
CURL_OK = (0, 6, 7, 28, 35, 52, 56)  # resolved, refused, timed out, TLS or empty reply
NMAP_OK = (0, 1)

# ---------------------------------------------------------------------------
# Command and screenshot definitions
# ---------------------------------------------------------------------------


def C(text, ok=(0,), timeout=180, net=None, target=None, kube=False, setup=False,
      dynamic=False):
    """One command.

    net:     "nmap", "curl", "dns" or "app" for a network test.
    target:  the scan target, which must still resolve into scope.
    kube:    needs a working kubeconfig.
    setup:   allowed to write the run private kubeconfig.
    dynamic: the host is read at run time out of a gcloud describe of a named
             in scope resource, so it is that resource's own address and cannot
             be pointed anywhere else.
    """
    return {"text": text, "ok": list(ok), "timeout": timeout, "net": net,
            "target": target, "kube": kube, "setup": setup, "dynamic": dynamic,
            "route": None}


def Shot(title, cmds):
    return {"title": title, "cmds": list(cmds)}


def nmap(ports, target, extra=""):
    return C("nmap -Pn -sT %s -p %s %s" % (extra, ports, target), ok=NMAP_OK,
             timeout=600, net="nmap", target=target)


def curl(url, target, method=""):
    flag = {"": "", "HEAD": "-I ", "OPTIONS": "-X OPTIONS "}[method]
    return C("curl -sS -i -m 15 %s%s" % (flag, url), ok=CURL_OK, timeout=60,
             net="curl", target=target)


def K(text, ok=KUBE_ERR, timeout=180):
    return C(text, ok=ok, timeout=timeout, kube=True)


def app(text, target, timeout=120, route=True):
    """An application layer request against one of the three in scope endpoints.

    route marks the command as exercising the route under test, so --app-path
    can swap it. Test case 43 passes route=False: the paths in its word list are
    the thing being discovered, not a route to be rewritten, and one of them is
    the default route itself.
    """
    cmd = C(text, ok=CURL_OK, timeout=timeout, net="app", target=target)
    cmd["route"] = APP_PATH if (route and APP_PATH in text) else None
    return cmd


def dyn(text, net, ok=NMAP_OK, timeout=600):
    """A scan of an address discovered from the resource's own gcloud record."""
    return C(text, ok=ok, timeout=timeout, net=net, dynamic=True)


# The public address of the Cloud SQL instance, empty when it has none.
SQL_PUBLIC_IP = ("$(gcloud sql instances describe %s %s --flatten='ipAddresses[]' "
                 "--filter='ipAddresses.type=PRIMARY' --format='value(ipAddresses.ipAddress)')"
                 % (SQL_INSTANCE, P))
# The address clients use to reach the cluster control plane.
GKE_ENDPOINT = ("$(gcloud container clusters describe %s %s --location %s "
                "--format='value(endpoint)')" % (CLUSTER, P, REGION))


def gke(fields):
    return C("gcloud container clusters describe %s %s --location %s --format=\"yaml(%s)\""
             % (CLUSTER, P, REGION, fields), ok=GCLOUD_ERR)


def sql(fields):
    return C("gcloud sql instances describe %s %s --format=\"yaml(%s)\""
             % (SQL_INSTANCE, P, fields), ok=GCLOUD_ERR)


FW_TABLE = ("table(name,network.basename(),direction,priority,"
            "sourceRanges.list():label=SOURCE_RANGES,"
            "allowed[].map().firewall_rule().list():label=ALLOW,"
            "targetTags.list():label=TARGET_TAGS,disabled,logConfig.enable:label=LOGGING)")

OPEN_FW = ("--filter=\"direction=INGRESS AND (sourceRanges:0.0.0.0/0 OR sourceRanges:'::/0')\"")

IAM_TABLE = ("--flatten=\"bindings[].members\" "
             "--format=\"table(bindings.role,bindings.members)\" "
             "--sort-by=bindings.role")

# Service account keys, one line per key, showing the keys Augnito manages itself.
SA_KEY_LOOP = (
    "for sa in $(gcloud iam service-accounts list %s --format='value(email)'); do "
    "printf '\\n%%s\\n' \"$sa\"; "
    "gcloud iam service-accounts keys list --iam-account=\"$sa\" %s "
    "--managed-by=user --format='table(name.basename(),keyType,validAfterTime,validBeforeTime)'; "
    "done" % (P, P))

# Which service accounts a Kubernetes service account may impersonate.
WI_LOOP = (
    "for sa in $(gcloud iam service-accounts list %s --format='value(email)'); do "
    "b=$(gcloud iam service-accounts get-iam-policy \"$sa\" %s "
    "--flatten='bindings[].members' "
    "--filter='bindings.role:roles/iam.workloadIdentityUser' "
    "--format='value(bindings.members)'); "
    "if [ -n \"$b\" ]; then printf '%%s\\n  %%s\\n' \"$sa\" \"$b\"; fi; done" % (P, P))

BUCKET_LOOP = (
    "for b in $(gcloud storage buckets list %s --format='value(name)'); do "
    "printf '\\n=== gs://%%s ===\\n' \"$b\"; "
    "gcloud storage buckets describe \"gs://$b\" --format=yaml; "
    "done" % P)

BUCKET_IAM_LOOP = (
    "for b in $(gcloud storage buckets list %s --format='value(name)'); do "
    "printf '\\n=== gs://%%s ===\\n' \"$b\"; "
    "gcloud storage buckets get-iam-policy \"gs://$b\" --flatten='bindings[].members' "
    "--format='table(bindings.role,bindings.members)'; done" % P)

NAT_LOOP = (
    "for r in $(gcloud compute routers list %s --region %s --format='value(name)'); do "
    "printf '\\n=== router %%s ===\\n' \"$r\"; "
    "gcloud compute routers nats list --router=\"$r\" --region %s %s "
    "--format='table(name,natIpAllocateOption,sourceSubnetworkIpRangesToNat,logConfig.enable,logConfig.filter)'; "
    "done" % (P, REGION, REGION, P))

# Only the three in scope names are looked up. The client took augnito.ai and
# every other name under it out of scope, so no zone is ever dumped whole.
DNS_LOOP = (
    "for z in $(gcloud dns managed-zones list %s --format='value(name)'); do "
    "for n in %s; do "
    "gcloud dns record-sets list --zone=\"$z\" %s --name=\"$n.\" "
    "--format='table(name,type,ttl,rrdatas.list())' 2>/dev/null; "
    "done; done" % (P, " ".join(HOSTS), P))

# Kubernetes workloads that run with host level privilege.
PRIV_PODS = (
    "kubectl get pods -A -o custom-columns="
    "NS:.metadata.namespace,POD:.metadata.name,"
    "PRIVILEGED:.spec.containers[*].securityContext.privileged,"
    "ROOT:.spec.securityContext.runAsNonRoot,"
    "HOSTNET:.spec.hostNetwork,HOSTPID:.spec.hostPID,HOSTIPC:.spec.hostIPC")

# Service account tokens mounted into pods that never call the API server.
SA_TOKENS = (
    "kubectl get pods -A -o custom-columns="
    "NS:.metadata.namespace,POD:.metadata.name,"
    "SERVICEACCOUNT:.spec.serviceAccountName,"
    "AUTOMOUNT:.spec.automountServiceAccountToken")

CLUSTER_ADMINS = (
    "kubectl get clusterrolebindings -o custom-columns="
    "NAME:.metadata.name,ROLE:.roleRef.name,"
    "SUBJECTS:.subjects[*].name,KINDS:.subjects[*].kind "
    "--no-headers | grep -E 'cluster-admin|system:masters' || echo "
    "'no binding to cluster-admin or system:masters'")

# Secret inventory by name, type and key count. Values are never requested.
SECRET_INVENTORY = (
    "kubectl get secrets -A --field-selector type!=kubernetes.io/service-account-token "
    "-o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type,KEYS:.data")

# Plain environment variables in pod specs that look like credentials, names only.
ENV_SECRETS = (
    "kubectl get pods -A -o custom-columns="
    "NS:.metadata.namespace,POD:.metadata.name,"
    "ENV_NAMES:.spec.containers[*].env[*].name "
    "--no-headers | grep -iE 'pass|secret|token|key|cred' || echo "
    "'no credential shaped environment variable names in pod specs'")

NS_PSA = (
    "kubectl get namespaces -o custom-columns="
    "NAME:.metadata.name,"
    "ENFORCE:.metadata.labels.pod-security\\.kubernetes\\.io/enforce,"
    "AUDIT:.metadata.labels.pod-security\\.kubernetes\\.io/audit,"
    "WARN:.metadata.labels.pod-security\\.kubernetes\\.io/warn")


SESSION = Shot("Tester session: date, gcloud configuration and active identity", [
    C("date"),
    C("gcloud version"),
    C("gcloud config list"),
    C("gcloud auth list"),
    C("gcloud projects describe %s --format=\"yaml(projectId,projectNumber,lifecycleState,parent)\"" % PROJECT,
      ok=GCLOUD_ERR),
])

# Paths probed to find out which routes Kong actually publishes. Each is quoted
# so the shell treats it as a literal.
APP_PATHS = " ".join("'%s'" % p for p in [
    "/", "/api", "/api/v1", "/v1", "/v2", "/health", "/healthz", "/ready",
    "/status", "/metrics", "/admin", "/auth", "/login", "/oauth/token",
    "/users", "/me", "/swagger", "/swagger-ui.html", "/openapi.json",
    "/api-docs", "/v3/api-docs", "/graphql", "/actuator", "/actuator/health",
    "/actuator/env", "/debug", "/.env", "/.git/config", "/server-status",
])
# The route the application test cases exercise. Point it at a real route with
# --app-path once test case 43 or the client's API documentation names one.
APP_PATH = "/api/v1"
# RFC 2606 reserved, so it can never resolve and is never contacted.
CORS_ORIGIN = "https://attacker.invalid"


def probe_paths(host):
    return app("for p in %s; do printf '%%-22s ' \"$p\"; "
               "curl -sS -o /dev/null -m 10 "
               "-w '%%{http_code}  %%{size_download}B  %%{content_type}\\n' "
               "\"https://%s$p\"; done" % (APP_PATHS, host), host, timeout=600, route=False)


# ---------------------------------------------------------------------------
# Test cases
#
# Each entry is (number, title, [screenshots]). The title becomes the folder
# name, so it reads as the finding it would support if the check fails.
# ---------------------------------------------------------------------------
TESTS = [
    # --- Discovery -------------------------------------------------------
    (1, "Project Inventory and Enabled Service Attack Surface", [
        Shot("Enabled APIs on project %s" % PROJECT, [
            C("gcloud services list --enabled %s --format=\"table(config.name,config.title)\"" % P,
              ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Every resource the granted identity can see in the project", [
            C("gcloud asset search-all-resources --scope=projects/%s "
              "--format=\"table(assetType,displayName,location,state)\" --sort-by=assetType --limit=400"
              % PROJECT, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),

    # --- GKE -------------------------------------------------------------
    (2, "GKE Control Plane Reachable from the Internet", [
        Shot("Clusters in the project and their endpoint configuration", [
            C("gcloud container clusters list %s --format=\"table(name,location,status,"
              "currentMasterVersion,privateClusterConfig.enablePrivateNodes:label=PRIVATE_NODES,"
              "privateClusterConfig.enablePrivateEndpoint:label=PRIVATE_ENDPOINT,endpoint)\"" % P,
              ok=GCLOUD_ERR),
        ]),
        Shot("%s: private cluster settings and master authorised networks" % CLUSTER, [
            gke("name,location,endpoint,privateClusterConfig,masterAuthorizedNetworksConfig,"
                "controlPlaneEndpointsConfig,networkConfig.defaultSnatStatus"),
        ]),
        Shot("%s: the control plane address, then that address tested from the internet" % CLUSTER, [
            C("gcloud container clusters describe %s %s --location %s "
              "--format=\"value(privateClusterConfig.publicEndpoint,endpoint)\"" % (CLUSTER, P, REGION),
              ok=GCLOUD_ERR),
            dyn("nmap -Pn -sT -p 443 %s" % GKE_ENDPOINT, "nmap"),
            dyn("curl -sS -i -m 15 -k https://%s/version" % GKE_ENDPOINT, "curl",
                ok=CURL_OK, timeout=60),
        ]),
    ]),
    (3, "GKE Cluster Hardening Controls Not Enabled", [
        Shot("%s: network policy, binary authorisation, Workload Identity and secret encryption" % CLUSTER, [
            gke("networkPolicy,addonsConfig.networkPolicyConfig,binaryAuthorization,"
                "workloadIdentityConfig,databaseEncryption,legacyAbac,shieldedNodes,"
                "networkConfig.enableIntraNodeVisibility,networkConfig.datapathProvider,"
                "confidentialNodes,autopilot,ipAllocationPolicy.useIpAliases"),
        ]),
        Shot("%s: legacy client certificate and static password authentication" % CLUSTER, [
            gke("masterAuth.clientCertificateConfig,masterAuth.username,masterAuth.password,"
                "securityPostureConfig,enableKubernetesAlpha"),
        ]),
    ]),
    (4, "GKE Node Pools Run Without Shielded VM and Metadata Protection", [
        Shot("%s: node pool image, shielded VM settings and metadata" % CLUSTER, [
            C("gcloud container node-pools list --cluster %s %s --location %s "
              "--format=\"table(name,version,config.imageType,config.machineType,"
              "config.shieldedInstanceConfig.enableSecureBoot:label=SECURE_BOOT,"
              "config.shieldedInstanceConfig.enableIntegrityMonitoring:label=INTEGRITY_MON)\""
              % (CLUSTER, P, REGION), ok=GCLOUD_ERR),
            gke("nodePools[].name,nodePools[].config.metadata,nodePools[].config.shieldedInstanceConfig,"
                "nodePools[].networkConfig.enablePrivateNodes"),
        ]),
    ]),
    (5, "GKE Node Service Account Over Privileged or Default", [
        Shot("%s: service account and OAuth scopes on every node pool" % CLUSTER, [
            gke("nodePools[].name,nodePools[].config.serviceAccount,nodePools[].config.oauthScopes"),
        ]),
        Shot("Project roles held by the node and Workload Identity service accounts", [
            C("gcloud projects get-iam-policy %s %s --filter=\"bindings.members:serviceAccount\""
              % (PROJECT, IAM_TABLE), ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),
    (6, "GKE Version Currency and Automatic Upgrade Management", [
        Shot("%s: running versions against the versions Google currently offers" % CLUSTER, [
            gke("currentMasterVersion,currentNodeVersion,releaseChannel,"
                "nodePools[].name,nodePools[].version,nodePools[].management"),
            C("gcloud container get-server-config %s --location %s "
              "--format=\"yaml(defaultClusterVersion,validMasterVersions[:6],channels)\"" % (P, REGION),
              ok=GCLOUD_ERR),
        ]),
    ]),
    (7, "GKE Cluster Logging and Monitoring Coverage", [
        Shot("%s: logging and monitoring services and components" % CLUSTER, [
            gke("loggingService,monitoringService,loggingConfig,monitoringConfig,"
                "notificationConfig,maintenancePolicy"),
        ]),
    ]),

    # --- Kubernetes (in cluster) ----------------------------------------
    (8, "Kubernetes Authorisation Granted to the Assessment Identity", [
        Shot("Cluster credentials and what this identity is permitted to do", [
            C("gcloud container clusters get-credentials %s %s --location %s"
              % (CLUSTER, P, REGION), ok=GCLOUD_ERR, setup=True),
            K("kubectl cluster-info"),
            K("kubectl auth can-i --list", timeout=300),
        ]),
    ]),
    (9, "Kubernetes RBAC Grants Cluster Administrator Rights Broadly", [
        Shot("Bindings to cluster-admin and system:masters", [
            K(CLUSTER_ADMINS),
            K("kubectl get clusterrolebindings -o custom-columns="
              "NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name", timeout=300),
        ]),
        Shot("Namespaced role bindings and the service accounts behind them", [
            K("kubectl get rolebindings -A -o custom-columns="
              "NS:.metadata.namespace,NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name",
              timeout=300),
        ]),
    ]),
    (10, "Kubernetes Workloads Run with Host Level Privilege", [
        Shot("Pods with privileged containers, host network, host PID or host IPC", [
            K(PRIV_PODS, timeout=300),
        ]),
        Shot("Pod Security Admission labels on every namespace", [
            K(NS_PSA),
        ]),
    ]),
    (11, "Kubernetes Service Account Tokens Mounted Into Every Pod", [
        Shot("Service account and token automount on every pod", [
            K(SA_TOKENS, timeout=300),
            K("kubectl get serviceaccounts -A -o custom-columns="
              "NS:.metadata.namespace,NAME:.metadata.name,"
              "AUTOMOUNT:.automountServiceAccountToken,"
              "GCP_SA:.metadata.annotations.iam\\.gke\\.io/gcp-service-account", timeout=300),
        ]),
    ]),
    (12, "Kubernetes Secrets Inventory and Credentials in Pod Specifications", [
        Shot("Secrets by namespace, name and type (values are never requested)", [
            K(SECRET_INVENTORY, timeout=300),
        ]),
        Shot("Credential shaped environment variable names in pod specifications", [
            K(ENV_SECRETS, timeout=300),
        ]),
    ]),
    (13, "Kubernetes Services Exposed Beyond the Cluster", [
        Shot("Services of type LoadBalancer and NodePort across all namespaces", [
            K("kubectl get svc -A -o wide", timeout=300),
        ]),
        Shot("Ingress resources and the hosts they publish", [
            K("kubectl get ingress -A -o custom-columns="
              "NS:.metadata.namespace,NAME:.metadata.name,CLASS:.spec.ingressClassName,"
              "HOSTS:.spec.rules[*].host,ADDRESS:.status.loadBalancer.ingress[*].ip", timeout=300),
        ]),
    ]),
    (14, "Kubernetes Network Policy Coverage Between Workloads", [
        Shot("Network policies against the namespaces that run workloads", [
            K("kubectl get networkpolicies -A"),
            K("kubectl get namespaces"),
        ]),
    ]),
    (15, "Kong Gateway Configuration Inside the Cluster", [
        Shot("Kong workloads, services and the admin API service type", [
            K("kubectl get pods,svc -A -o wide --selector='app.kubernetes.io/name=kong'"),
            K("kubectl get svc -A --no-headers | grep -i kong || echo 'no service with kong in its name'"),
        ]),
        Shot("Kong custom resources and the plugins that are configured", [
            K("kubectl api-resources --api-group=configuration.konghq.com"),
            K("kubectl get kongplugins,kongclusterplugins -A -o custom-columns="
              "NS:.metadata.namespace,NAME:.metadata.name,PLUGIN:.plugin,DISABLED:.disabled"),
        ]),
    ]),

    # --- Cloud SQL -------------------------------------------------------
    (16, "Cloud SQL Instance Reachable Beyond the VPC", [
        Shot("%s: public IP, private network and authorised networks" % SQL_INSTANCE, [
            C("gcloud sql instances list %s --format=\"table(name,databaseVersion,region,"
              "settings.ipConfiguration.ipv4Enabled:label=PUBLIC_IP,"
              "settings.ipConfiguration.privateNetwork:label=PRIVATE_NETWORK,state)\"" % P,
              ok=GCLOUD_ERR),
            sql("name,region,databaseVersion,state,ipAddresses,settings.ipConfiguration"),
        ]),
        Shot("%s: MySQL 3306 on its public address, tested from the internet "
             "(no output above means the instance has no public address)" % SQL_INSTANCE, [
            dyn("nmap -Pn -sT -p 3306 %s" % SQL_PUBLIC_IP, "nmap"),
        ]),
    ]),
    (17, "Cloud SQL Connections Not Required to Use TLS", [
        Shot("%s: SSL mode, server certificate and Cloud SQL Auth proxy settings" % SQL_INSTANCE, [
            sql("settings.ipConfiguration.requireSsl,settings.ipConfiguration.sslMode,"
                "settings.ipConfiguration.enablePrivatePathForGoogleCloudServices,"
                "serverCaCert.expirationTime,serverCaCert.createTime"),
        ]),
    ]),
    (18, "Cloud SQL Backup, Recovery and Deletion Protection", [
        Shot("%s: automated backups, point in time recovery and binary logging" % SQL_INSTANCE, [
            sql("settings.backupConfiguration,settings.deletionProtectionEnabled,"
                "settings.availabilityType,settings.storageAutoResize,settings.dataDiskSizeGb"),
        ]),
    ]),
    (19, "Cloud SQL Database Flags and Account Hygiene", [
        Shot("%s: database flags against the MySQL benchmark" % SQL_INSTANCE, [
            sql("databaseVersion,settings.databaseFlags,settings.maintenanceWindow,"
                "settings.insightsConfig,settings.tier"),
        ]),
        Shot("%s: database accounts by name and host (passwords are never requested)" % SQL_INSTANCE, [
            C("gcloud sql users list --instance %s %s --format=\"table(name,host,type)\""
              % (SQL_INSTANCE, P), ok=GCLOUD_ERR),
            C("gcloud sql databases list --instance %s %s --format=\"table(name,charset,collation)\""
              % (SQL_INSTANCE, P), ok=GCLOUD_ERR),
        ]),
    ]),
    (20, "Cloud SQL Encryption at Rest Uses Google Managed Keys Only", [
        Shot("%s: disk encryption configuration" % SQL_INSTANCE, [
            sql("diskEncryptionConfiguration,diskEncryptionStatus,settings.dataDiskType"),
        ]),
    ]),

    # --- Cloud Storage ---------------------------------------------------
    (21, "Cloud Storage Buckets Open to Unauthenticated Users", [
        Shot("Buckets in the project and their public access controls", [
            C("gcloud storage buckets list %s --format=\"table(name,location,storage_class,"
              "uniform_bucket_level_access,public_access_prevention)\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("IAM policy on every bucket, looking for allUsers and allAuthenticatedUsers", [
            C(BUCKET_IAM_LOOP, ok=GCLOUD_ERR, timeout=900),
        ]),
    ]),
    (22, "Cloud Storage Data Protection Settings", [
        Shot("Versioning, retention, soft delete, CMEK and access logging on every bucket", [
            C(BUCKET_LOOP, ok=GCLOUD_ERR, timeout=900),
        ]),
    ]),

    # --- Artifact Registry ----------------------------------------------
    (23, "Artifact Registry Repository Access Control", [
        Shot("Repositories in %s and their configuration" % REGION, [
            C("gcloud artifacts repositories list %s --format=\"table(name.basename(),format,mode,"
              "location,kmsKeyName,dockerConfig.immutableTags:label=IMMUTABLE_TAGS)\"" % P,
              ok=GCLOUD_ERR, timeout=300),
            C("gcloud artifacts repositories describe %s %s --location %s "
              "--format=\"yaml(name,format,mode,kmsKeyName,cleanupPolicies,dockerConfig,"
              "vulnerabilityScanningConfig,satisfiesPzi)\"" % (AR_REPO, P, REGION), ok=GCLOUD_ERR),
        ]),
        Shot("IAM policy on the %s repository, looking for public readers" % AR_REPO, [
            C("gcloud artifacts repositories get-iam-policy %s %s --location %s "
              "--flatten=\"bindings[].members\" --format=\"table(bindings.role,bindings.members)\""
              % (AR_REPO, P, REGION), ok=GCLOUD_ERR),
        ]),
    ]),
    (24, "Container Images Not Scanned for Known Vulnerabilities", [
        Shot("Images in the %s repository and when they were last pushed" % AR_REPO, [
            C("gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s %s "
              "--include-tags --format=\"table(package,tags,updateTime.date('%%Y-%%m-%%d'),sizeBytes)\" "
              "--limit=60" % (REGION, PROJECT, AR_REPO, P), ok=GCLOUD_ERR, timeout=600),
        ]),
        Shot("Vulnerability scanning results recorded against those images", [
            C("gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s %s "
              "--show-occurrences --occurrence-filter='kind=\"VULNERABILITY\"' "
              "--format=\"table(package,tags,vulnerability_counts)\" --limit=25"
              % (REGION, PROJECT, AR_REPO, P), ok=GCLOUD_ERR, timeout=900),
            C("gcloud services list --enabled %s --filter=\"config.name~containerscanning OR "
              "config.name~containeranalysis OR config.name~binaryauthorization\" "
              "--format=\"table(config.name,config.title)\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),

    # --- Network ---------------------------------------------------------
    (25, "Firewall Rules Permit Unrestricted Inbound Access from the Internet", [
        Shot("Ingress rules whose source range is 0.0.0.0/0 or ::/0", [
            C("gcloud compute firewall-rules list %s %s --format='%s'" % (P, OPEN_FW, FW_TABLE),
              ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Every firewall rule in the project, for completeness", [
            C("gcloud compute firewall-rules list %s --format='%s' --sort-by=priority" % (P, FW_TABLE),
              ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),
    (26, "Firewall and VPC Flow Logging Not Enabled", [
        Shot("Firewall rules with rule logging switched off", [
            C("gcloud compute firewall-rules list %s --format=\"table(name,direction,priority,"
              "logConfig.enable:label=RULE_LOGGING)\" --sort-by=name" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Flow logs and Private Google Access on the subnets", [
            C("gcloud compute networks subnets list %s --filter=\"region:%s\" "
              "--format=\"table(name,region.basename(),ipCidrRange,privateIpGoogleAccess,"
              "logConfig.enable:label=FLOW_LOGS,purpose)\"" % (P, REGION), ok=GCLOUD_ERR, timeout=300),
            C("gcloud compute networks subnets describe %s %s --region %s "
              "--format=\"yaml(name,ipCidrRange,privateIpGoogleAccess,logConfig,secondaryIpRanges,purpose)\""
              % (SUBNET, P, REGION), ok=GCLOUD_ERR),
        ]),
    ]),
    (27, "VPC Topology, Routes and Cloud NAT Configuration", [
        Shot("Networks, peerings and the routes that reach the internet", [
            C("gcloud compute networks list %s --format=\"table(name,subnet_mode,bgp_routing_mode,"
              "IPV4_RANGE,GATEWAY_IPV4)\"" % P, ok=GCLOUD_ERR, timeout=300),
            C("gcloud compute routes list %s --filter=\"destRange=0.0.0.0/0\" "
              "--format=\"table(name,network.basename(),destRange,nextHopGateway.basename(),"
              "nextHopInstance.basename(),priority)\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Cloud NAT gateways and whether their logging is enabled", [
            C(NAT_LOOP, ok=GCLOUD_ERR, timeout=600),
        ]),
    ]),

    # --- IAM -------------------------------------------------------------
    (28, "Primitive Roles and External Identities in the Project IAM Policy", [
        Shot("Every role binding on project %s" % PROJECT, [
            C("gcloud projects get-iam-policy %s %s" % (PROJECT, IAM_TABLE), ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Owner, editor and viewer bindings, and members outside the organisation", [
            C("gcloud projects get-iam-policy %s %s --filter=\"bindings.role:roles/owner OR "
              "bindings.role:roles/editor OR bindings.role:roles/viewer\"" % (PROJECT, IAM_TABLE),
              ok=GCLOUD_ERR, timeout=300),
            C("gcloud projects get-iam-policy %s --flatten=\"bindings[].members\" "
              "--format=\"value(bindings.members)\" --filter=\"bindings.members:gmail.com OR "
              "bindings.members:allUsers OR bindings.members:allAuthenticatedUsers\" "
              "| sort -u || echo 'no gmail.com, allUsers or allAuthenticatedUsers member'"
              % PROJECT, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),
    (29, "Service Accounts and User Managed Keys", [
        Shot("Service accounts in the project", [
            C("gcloud iam service-accounts list %s --format=\"table(email,displayName,disabled)\"" % P,
              ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("User managed keys on each service account, with their age", [
            C(SA_KEY_LOOP, ok=GCLOUD_ERR, timeout=900),
        ]),
    ]),
    (30, "Workload Identity Bindings Between Kubernetes and GCP", [
        Shot("Cluster Workload Identity pool and the bindings that use it", [
            gke("workloadIdentityConfig,nodePools[].config.workloadMetadataConfig"),
            C(WI_LOOP, ok=GCLOUD_ERR, timeout=900),
        ]),
    ]),
    (31, "Organisation Policy Constraints and Audit Logging", [
        Shot("Organisation policy constraints applied to the project", [
            C("gcloud resource-manager org-policies list --project=%s "
              "--format=\"table(constraint,listPolicy.allValues,booleanPolicy.enforced)\"" % PROJECT,
              ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Data access audit log configuration on the project IAM policy", [
            C("gcloud projects get-iam-policy %s --format=\"yaml(auditConfigs)\"" % PROJECT,
              ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),

    # --- Load balancing, DNS, logging ------------------------------------
    (32, "Load Balancer TLS Policy and Cloud Armor Protection", [
        Shot("HTTPS proxies, the SSL policies behind them and the certificates in use", [
            C("gcloud compute target-https-proxies list %s --format=\"table(name,urlMap.basename(),"
              "sslPolicy.basename(),sslCertificates.len():label=CERTS,quicOverride)\"" % P,
              ok=GCLOUD_ERR, timeout=300),
            C("gcloud compute ssl-policies list %s --format=\"table(name,profile,minTlsVersion,"
              "customFeatures.list())\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Cloud Armor policies and the backend services they protect", [
            C("gcloud compute security-policies list %s --format=\"table(name,type,"
              "rules.len():label=RULES)\"" % P, ok=GCLOUD_ERR, timeout=300),
            C("gcloud compute backend-services list %s --format=\"table(name,protocol,loadBalancingScheme,"
              "securityPolicy.basename():label=CLOUD_ARMOR,enableCDN,logConfig.enable:label=LOGGING,"
              "iap.enabled:label=IAP)\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Forwarding rules, including the rule that holds %s" % LB_IP, [
            C("gcloud compute forwarding-rules list %s --format=\"table(name,region.basename(),"
              "IPAddress,IPProtocol,portRange,target.basename(),loadBalancingScheme)\"" % P,
              ok=GCLOUD_ERR, timeout=300),
            C("gcloud compute addresses list %s --format=\"table(name,address,addressType,"
              "region.basename(),status,users.len():label=IN_USE_BY)\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),
    (33, "Cloud DNS Zone Configuration and DNSSEC", [
        Shot("Managed zones and whether DNSSEC is signed", [
            C("gcloud dns managed-zones list %s --format=\"table(name,dnsName,visibility,"
              "dnssecConfig.state:label=DNSSEC)\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Records for the three in scope names only", [
            C(DNS_LOOP, ok=GCLOUD_ERR, timeout=600),
        ]),
    ]),
    (34, "Log Retention, Sinks and Alerting", [
        Shot("Log buckets, their retention and the sinks that export logs", [
            C("gcloud logging buckets list %s --format=\"table(name,location,retentionDays,"
              "lifecycleState,cmekSettings.kmsKeyName)\"" % P, ok=GCLOUD_ERR, timeout=300),
            C("gcloud logging sinks list %s --format=\"table(name,destination,filter)\"" % P,
              ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Log based metrics and alerting policies", [
            C("gcloud logging metrics list %s --format=\"table(name,filter)\"" % P,
              ok=GCLOUD_ERR, timeout=300),
            C("gcloud alpha monitoring policies list %s --format=\"table(displayName,enabled,"
              "conditions.len():label=CONDITIONS)\" 2>&1 | head -40" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),

    # --- External, unauthenticated ---------------------------------------
    (35, "External Attack Surface of the Public Load Balancer", [
        Shot("The three published hostnames and the address behind them", [
            C("for h in %s; do printf '%%-34s ' \"$h\"; "
              "getent ahostsv4 \"$h\" | awk '{print $1}' | sort -u | tr '\\n' ' '; echo; done"
              % " ".join(HOSTS), net="dns", target=HOSTS[0]),
            C("dig +short %s" % " ".join(HOSTS), ok=GCLOUD_ERR, net="dns", target=HOSTS[0]),
        ]),
        Shot("%s: TCP ports reachable from the internet" % LB_IP, [
            nmap("80,443,8000,8001,8443,8444,9080,9443,3306,6379,27017,9200,5601", LB_IP,
                 extra="-sV --version-light"),
        ]),
        Shot("%s: wider port sweep" % LB_IP, [
            nmap("--top-ports 200", LB_IP),
        ]),
    ]),
    (36, "Kong Gateway Admin API and Status Endpoints Exposed", [
        Shot("Kong admin API ports tested from the internet", [
            curl("http://%s:8001/" % LB_IP, LB_IP),
            curl("https://%s:8444/ -k" % LB_IP, LB_IP),
        ]),
        Shot("Kong status, metrics and default route behaviour on each hostname", [
            curl("https://%s/status" % HOSTS[0], HOSTS[0]),
            curl("https://%s/metrics" % HOSTS[0], HOSTS[0]),
            curl("https://%s/this-route-should-not-exist" % HOSTS[0], HOSTS[0]),
        ]),
    ]),
    (37, "TLS Configuration of the Published Endpoints", [
        Shot("Certificate, protocol and cipher negotiated on each hostname", [
            C("for h in %s; do printf '\\n=== %%s ===\\n' \"$h\"; "
              "openssl s_client -connect \"$h\":443 -servername \"$h\" -brief </dev/null 2>&1 "
              "| head -20; done" % " ".join(HOSTS), ok=CURL_OK, timeout=180,
              net="curl", target=HOSTS[0]),
        ]),
        Shot("Legacy protocol support on %s" % HOSTS[0], [
            C("for v in tls1 tls1_1 tls1_2 tls1_3; do printf '%%-8s ' \"$v\"; "
              "if openssl s_client -connect %s:443 -servername %s -\"$v\" -brief </dev/null "
              ">/dev/null 2>&1; then echo ACCEPTED; else echo rejected; fi; done"
              % (HOSTS[0], HOSTS[0]), ok=CURL_OK, timeout=180, net="curl", target=HOSTS[0]),
        ]),
    ]),
    (38, "HTTP Security Headers and Methods on the Published Endpoints", [
        Shot("Response headers returned by each hostname", [
            curl("https://%s/" % HOSTS[0], HOSTS[0], method="HEAD"),
            curl("https://%s/" % HOSTS[1], HOSTS[1], method="HEAD"),
            curl("https://%s/" % HOSTS[2], HOSTS[2], method="HEAD"),
        ]),
        Shot("Methods advertised and whether plain HTTP is redirected", [
            curl("https://%s/" % HOSTS[0], HOSTS[0], method="OPTIONS"),
            curl("http://%s/" % HOSTS[2], HOSTS[2], method="HEAD"),
        ]),
        Shot("Files that are commonly left reachable", [
            curl("https://%s/robots.txt" % HOSTS[2], HOSTS[2]),
            curl("https://%s/.well-known/security.txt" % HOSTS[2], HOSTS[2]),
        ]),
    ]),

    # --- Gaps closed after the 27 Oct 2026 scope walk --------------------
    (39, "Compute Engine Instances and Public Addresses", [
        Shot("Every instance in the project, across all three zones", [
            C("gcloud compute instances list %s --format=\"table(name,zone.basename(),status,"
              "machineType.basename(),networkInterfaces[0].networkIP:label=INTERNAL_IP,"
              "networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP,"
              "tags.items.list():label=TAGS)\" --sort-by=zone" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Instances that hold a public address, and the service accounts they run as", [
            C("gcloud compute instances list %s "
              "--filter=\"networkInterfaces[0].accessConfigs[0].natIP:*\" "
              "--format=\"table(name,zone.basename(),"
              "networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP,"
              "tags.items.list():label=TAGS)\"" % P, ok=GCLOUD_ERR, timeout=300),
            C("gcloud compute instances list %s --format=\"table(name,zone.basename(),"
              "serviceAccounts[0].email:label=SERVICE_ACCOUNT,"
              "serviceAccounts[0].scopes.list():label=SCOPES)\"" % P, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),
    (40, "VPC Peering and Private Service Access to Cloud SQL", [
        Shot("Peerings on %s and the routes they exchange" % VPC, [
            C("gcloud compute networks peerings list %s --network %s --format=yaml"
              % (P, VPC), ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Address ranges reserved for private service access", [
            C("gcloud compute addresses list %s --global "
              "--format=\"table(name,address,prefixLength,purpose,status,network.basename())\""
              % P, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),
    (41, "Custom IAM Roles and the Rights of the Assessment Identity", [
        Shot("Custom roles defined in the project", [
            C("gcloud iam roles list --project %s "
              "--format=\"table(name.basename(),title,stage)\"" % PROJECT,
              ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Permissions carried by each custom role", [
            C("for r in $(gcloud iam roles list --project %s --format='value(name.basename())'); do "
              "printf '\\n=== %%s ===\\n' \"$r\"; "
              "gcloud iam roles describe \"$r\" --project %s "
              "--format='yaml(title,stage,includedPermissions)'; done" % (PROJECT, PROJECT),
              ok=GCLOUD_ERR, timeout=600),
        ]),
        Shot("What the %s grant actually resolves to for this account" % GRANTED_ROLE, [
            C("gcloud projects get-iam-policy %s --flatten=\"bindings[].members\" "
              "--format=\"table(bindings.role,bindings.members)\" "
              "--filter=\"bindings.members:$(gcloud config list --format='value(core.account)')\""
              % PROJECT, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),
    (42, "Over Privilege Reported by Google's Own IAM Analysis", [
        Shot("IAM policy recommendations, based on 90 days of real usage", [
            C("gcloud recommender recommendations list --project=%s --location=global "
              "--recommender=google.iam.policy.Recommender "
              "--format=\"table(name.basename(),primaryImpact.category,stateInfo.state,description)\""
              % PROJECT, ok=GCLOUD_ERR, timeout=300),
        ]),
        Shot("Service account insights, including unused accounts and keys", [
            C("gcloud recommender insights list --project=%s --location=global "
              "--insight-type=google.iam.serviceAccount.Insight "
              "--format=\"table(name.basename(),category,stateInfo.state,description)\""
              % PROJECT, ok=GCLOUD_ERR, timeout=300),
        ]),
    ]),

    # --- Application layer, in scope for the three endpoints -------------
    (43, "Routes Published by the Gateway", [
        Shot("%s: which paths answer, by status, size and content type" % HOSTS[0],
             [probe_paths(HOSTS[0])]),
        Shot("%s: which paths answer, by status, size and content type" % HOSTS[1],
             [probe_paths(HOSTS[1])]),
        Shot("%s: which paths answer, by status, size and content type" % HOSTS[2],
             [probe_paths(HOSTS[2])]),
    ]),
    (44, "Authentication Enforced at the Gateway", [
        Shot("%s: no credential, a bogus bearer token and a bogus API key" % h, [
            app("curl -sS -i -m 15 https://%s%s" % (h, APP_PATH), h),
            app("curl -sS -i -m 15 -H 'Authorization: Bearer invalid.token.value' "
                "https://%s%s" % (h, APP_PATH), h),
            app("curl -sS -i -m 15 -H 'apikey: invalid-key' https://%s%s" % (h, APP_PATH), h),
        ]) for h in HOSTS
    ]),
    (45, "HTTP Method and Verb Tampering", [
        Shot("%s: the same route asked for with each method "
             "(DELETE is left to manual testing)" % HOSTS[0], [
            app("curl -sS -i -m 15 -X GET https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
            app("curl -sS -i -m 15 -X POST https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
            app("curl -sS -i -m 15 -X PUT https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
            app("curl -sS -i -m 15 -X PATCH https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
        ]),
        Shot("%s: method override headers, which some gateways honour" % HOSTS[0], [
            app("curl -sS -i -m 15 -H 'X-HTTP-Method-Override: PUT' "
                "https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
            app("curl -sS -i -m 15 -H 'X-Original-URL: /admin' "
                "https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
        ]),
    ]),
    (46, "Cross Origin Resource Sharing Policy", [
        Shot("%s: whether an unknown origin is reflected back" % h, [
            app("curl -sS -i -m 15 -H 'Origin: %s' https://%s/" % (CORS_ORIGIN, h), h),
            app("curl -sS -i -m 15 -X OPTIONS -H 'Origin: %s' "
                "-H 'Access-Control-Request-Method: POST' "
                "-H 'Access-Control-Request-Headers: authorization' "
                "https://%s%s" % (CORS_ORIGIN, h, APP_PATH), h),
        ]) for h in HOSTS
    ]),
    (47, "Rate Limiting and Request Throttling", [
        Shot("%s: status codes across a bounded burst of 30 requests" % h, [
            app("for i in $(seq 1 30); do curl -sS -o /dev/null -m 5 "
                "-w '%%{http_code} ' https://%s%s; done; echo" % (h, APP_PATH), h, timeout=300),
            app("curl -sS -i -m 15 https://%s%s | grep -iE "
                "'ratelimit|retry-after|x-kong' || echo 'no rate limit headers returned'"
                % (h, APP_PATH), h),
        ]) for h in HOSTS
    ]),
    (48, "Error Handling and Information Disclosure", [
        Shot("%s: malformed body, unexpected content type and a quote in a parameter" % HOSTS[0], [
            app("curl -sS -i -m 15 -X POST -H 'Content-Type: application/json' "
                "--data '{\"broken\":' https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
            app("curl -sS -i -m 15 -H 'Accept: application/xml' "
                "https://%s%s" % (HOSTS[0], APP_PATH), HOSTS[0]),
            app("curl -sS -i -m 15 'https://%s%s?id=%%27'" % (HOSTS[0], APP_PATH), HOSTS[0]),
        ]),
        Shot("%s: a path that cannot exist, to see what the gateway says" % HOSTS[0], [
            app("curl -sS -i -m 15 'https://%s/%%2e%%2e/%%2e%%2e/etc/passwd'" % HOSTS[0], HOSTS[0]),
            app("curl -sS -i -m 15 https://%s/nonexistent-%s" % (HOSTS[0], "probe"), HOSTS[0]),
        ]),
    ]),
]


# ---------------------------------------------------------------------------
# Guard: refuse anything that is not a read, or a network test outside scope
# ---------------------------------------------------------------------------
# gcloud verbs that only read. Anything else is refused before the run starts.
GCLOUD_READS = {
    "list", "describe", "get-iam-policy", "get-server-config", "version",
    "search-all-resources", "search-all-iam-policies", "list-tags", "get-config",
    "list-grantable-roles", "get-ancestors", "get-value", "print-settings",
}
# get-credentials only writes the kubeconfig this run owns, so it is allowed
# on a command that declares setup=True and nowhere else.
GCLOUD_SETUP = {"get-credentials"}
GCLOUD_WRITES = {
    "create", "delete", "update", "patch", "set", "set-iam-policy", "apply",
    "add-iam-policy-binding", "remove-iam-policy-binding", "enable", "disable",
    "deploy", "ssh", "scp", "import", "export", "copy-files", "reset",
    "start", "stop", "restart", "resize", "undelete", "move", "clone", "revoke",
    "login", "activate-service-account", "print-access-token", "print-identity-token",
    "add-tags", "remove-tags", "rotate", "simulate", "repair", "upgrade", "rollback",
}
KUBECTL_READS = {"get", "describe", "api-resources", "api-versions", "version",
                 "cluster-info", "explain", "top"}
KUBECTL_SUB = {"auth": {"can-i"}, "config": {"view"}}
KUBECTL_WRITES = {
    "create", "apply", "delete", "edit", "patch", "replace", "exec", "cp", "run",
    "port-forward", "proxy", "scale", "drain", "cordon", "uncordon", "label",
    "annotate", "attach", "taint", "rollout", "set", "expose", "autoscale", "debug",
    "wait", "kustomize", "diff", "certificate",
}
# Shell programs this tool never needs. Anything that writes, connects out or
# starts an interpreter is refused.
BLOCKED = re.compile(
    r"(?:^|[\s;|&(`/])(rm|mv|cp|dd|tee|wget|ssh|scp|nc|ncat|socat|telnet|ftp|sudo|su|"
    r"chmod|chown|kill|pkill|python|python3|perl|ruby|php|node|eval|exec|source|"
    r"crontab|systemctl|mount|mkfs|gsutil|bq|docker|crictl|helm|terraform|"
    r"bash|sh|zsh|xargs|env)"
    r"(?=\s|$)")
# A single quoted string cannot expand or substitute anything, so it is data and
# never a program. Double quotes still allow $( ), so they are left alone.
SQUOTED = re.compile(r"'[^']*'")
FILE_REDIRECT = re.compile(r">(?!&)(?!\s*/dev/null)")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# Hostnames with a real top level domain, so paths like security.txt are not
# mistaken for a host.
FQDN = re.compile(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:ai|com|net|org|io|dev|cloud|app|co)\b")
# Anything in a URL is a host whatever its top level domain, so an out of scope
# name the FQDN list does not know is still caught.
URL_HOST = re.compile(r"https?://([^/\s\"'>]+)")
# RFC 2606 keeps these from ever resolving, so a header value such as
# "Origin: https://attacker.invalid" names nothing that could be contacted.
RESERVED_TLD = (".invalid", ".test", ".example", ".localhost")
NET_TOOLS = {"nmap": {"nmap"}, "curl": {"curl", "openssl"}, "dns": {"dig", "getent"},
             "app": {"curl"}}
ALL_NET_TOOLS = re.compile(r"\b(nmap|curl|openssl|dig|getent|ping|traceroute|hping3|masscan|nikto)\b")
# On a configuration read curl may ask for a representation and nothing else.
CURL_WRITE_FLAGS = re.compile(r"\s(-d|-F|-T|--data\S*|--form|--upload-file|--json)\b")
# An application layer test may send a body, but never a file upload.
APP_WRITE_FLAGS = re.compile(r"\s(-T|-F|--form|--upload-file)\b")
# The token after -X is captured whatever it looks like, so a method hidden in
# a shell variable cannot slip past the allowed list.
CURL_METHOD = re.compile(r"(?:-X|--request)\s+(\S+)")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# DELETE is left out on purpose: it is the one method that can destroy UAT data
# without the tester seeing what it removed, so it stays a manual test.
APP_METHODS = SAFE_METHODS | {"POST", "PUT", "PATCH"}
# A dynamic scan may only take its address from one of these resources.
DYNAMIC_SOURCES = (CLUSTER, SQL_INSTANCE)
# Reading a secret as yaml or json would put its value in the evidence.
SECRET_DUMP = re.compile(r"secret", re.I)
STRUCTURED_OUT = re.compile(r"(?:-o|--output)[= ]\s*(?:yaml|json)\b|jsonpath")


class GuardError(Exception):
    pass


_OP = re.compile(r"[;|&)`<>]")


def _invocations(text, program):
    """Every invocation of one program inside a shell command, as
    (group and verb words, start, end) with the span the words occupy.

    The program is matched after whitespace, a shell operator, an opening
    bracket, a dollar sign or a slash, so a call inside $( ) or ` ` is found,
    and so is one invoked by its full path.
    """
    found = []
    pat = re.compile(r"(?:^|[\s;|&(`$/])" + re.escape(program) + r"(?=\s|$)")
    for m in pat.finditer(text):
        pos = m.end()
        words = []
        while pos < len(text):
            while pos < len(text) and text[pos] in " \t":
                pos += 1
            if pos >= len(text):
                break
            start = pos
            while pos < len(text) and text[pos] not in " \t":
                pos += 1
            raw = text[start:pos]
            if raw.startswith("-"):
                pos = start
                break
            hit = _OP.search(raw)
            head = (raw[:hit.start()] if hit else raw).strip("\'\"")
            if head:
                words.append(head)
            if hit:
                pos = start + hit.start()
                break
        found.append((words, m.end(), pos))
    return found


def net_hosts(text):
    """Every address and hostname a network command would contact."""
    hosts = set(IPV4.findall(text)) | set(FQDN.findall(text))
    for authority in URL_HOST.findall(text):
        host = authority.split("@")[-1]
        if not host.startswith("["):
            host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        # A substitution is resolved at run time and is handled by the dynamic
        # rule instead, so it is not a literal host.
        if any(ch in host for ch in "$(){}*"):
            continue
        if host:
            hosts.add(host)
    return {h for h in hosts if not h.endswith(RESERVED_TLD)}


def guard(cmd, where):
    text = cmd["text"]
    # The group chain of a gcloud or kubectl call belongs to that tool, not to
    # the shell, so it is blanked out before looking for shell programs. That
    # keeps "gcloud artifacts docker images list" from reading as a docker call.
    scrubbed = list(text)

    for words, start, end in _invocations(text, "gcloud"):
        scrubbed[start:end] = " " * (end - start)
        if not words:
            raise GuardError("%s: a gcloud call with no subcommand" % where)
        writes = [w for w in words if w in GCLOUD_WRITES]
        if writes:
            raise GuardError("%s: 'gcloud %s' is not a read only call (%s)"
                             % (where, " ".join(words), writes[0]))
        setup = [w for w in words if w in GCLOUD_SETUP]
        if setup:
            if not cmd["setup"]:
                raise GuardError("%s: 'gcloud %s' may only run as a declared setup step"
                                 % (where, " ".join(words)))
            continue
        if not any(w in GCLOUD_READS for w in words):
            raise GuardError("%s: 'gcloud %s' has no recognised read only verb"
                             % (where, " ".join(words)))

    for words, start, end in _invocations(text, "kubectl"):
        scrubbed[start:end] = " " * (end - start)
        if not words:
            raise GuardError("%s: a kubectl call with no subcommand" % where)
        verb = words[0]
        if verb in KUBECTL_SUB:
            sub = words[1] if len(words) > 1 else ""
            if sub not in KUBECTL_SUB[verb]:
                raise GuardError("%s: 'kubectl %s %s' is not allowed" % (where, verb, sub))
        elif verb in KUBECTL_WRITES or verb not in KUBECTL_READS:
            raise GuardError("%s: 'kubectl %s' is not a read only call" % (where, verb))
        later = [w for w in words[1:] if w in KUBECTL_WRITES]
        if later:
            raise GuardError("%s: 'kubectl %s' is not a read only call (%s)"
                             % (where, " ".join(words), later[0]))
        if SECRET_DUMP.search(text) and STRUCTURED_OUT.search(text):
            raise GuardError("%s: secrets may be listed but never dumped as yaml or json" % where)

    shell_text = SQUOTED.sub(lambda m: " " * len(m.group(0)), "".join(scrubbed))
    if BLOCKED.search(shell_text):
        raise GuardError("%s: blocked program '%s'" % (where, BLOCKED.search(shell_text).group(1)))
    if FILE_REDIRECT.search(text):
        raise GuardError("%s: output redirection to a file is not allowed" % where)

    tools = set(ALL_NET_TOOLS.findall(text))
    if tools and not cmd["net"]:
        raise GuardError("%s: network tool %s used outside a declared network test"
                         % (where, ", ".join(sorted(tools))))
    if cmd["net"]:
        if cmd["net"] not in NET_TOOLS:
            raise GuardError("%s: unknown network test type %r" % (where, cmd["net"]))
        extra = tools - NET_TOOLS[cmd["net"]]
        if extra:
            raise GuardError("%s: %s is not part of a %s test"
                             % (where, ", ".join(sorted(extra)), cmd["net"]))
        if "curl" in tools:
            if cmd["net"] == "app":
                if APP_WRITE_FLAGS.search(text):
                    raise GuardError("%s: an application test may not upload a file" % where)
                allowed = APP_METHODS
            else:
                if CURL_WRITE_FLAGS.search(text):
                    raise GuardError("%s: curl may not send a request body" % where)
                allowed = SAFE_METHODS
            for method in CURL_METHOD.findall(text):
                literal = method.strip("\"'")
                if literal not in allowed:
                    raise GuardError("%s: curl method %s is not allowed here (methods must be "
                                     "written out, not taken from a variable)" % (where, method))
        hosts = net_hosts(text)
        if cmd["dynamic"]:
            # The address is read out of the resource's own gcloud record, so the
            # command must name that resource and must not carry a literal host.
            if not any(("describe %s " % r) in text for r in DYNAMIC_SOURCES):
                raise GuardError("%s: a dynamic target must come from a describe of %s"
                                 % (where, " or ".join(DYNAMIC_SOURCES)))
            if hosts:
                raise GuardError("%s: a dynamic target may not also name a literal host (%s)"
                                 % (where, ", ".join(sorted(hosts))))
            return
        if not hosts:
            raise GuardError("%s: a network test must name the host it contacts" % where)
        outside = hosts - set(SCAN_TARGETS)
        if outside:
            raise GuardError("%s: out of scope host %s" % (where, ", ".join(sorted(outside))))


def guard_all():
    guard_shot(SESSION, "session")
    for num, _title, shots in TESTS:
        for i, shot in enumerate(shots, 1):
            guard_shot(shot, "test case %d screenshot %d" % (num, i))


def guard_shot(shot, where):
    for j, cmd in enumerate(shot["cmds"], 1):
        guard(cmd, "%s command %d" % (where, j))


# ---------------------------------------------------------------------------
# Terminal session (shared by both engines)
# ---------------------------------------------------------------------------
GLYPH = "㉿"


def kali_prompt(glyph):
    """The two line Kali prompt with the real user, host, folder and venv."""
    user = getpass.getuser()
    host = socket.gethostname().split(".")[0]
    root = os.geteuid() == 0
    home = os.path.expanduser("~").rstrip("/")
    cwd = os.getcwd()
    if cwd == home:
        path = "~"
    elif home and cwd.startswith(home + "/"):
        path = "~" + cwd[len(home):]
    else:
        path = cwd
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 6:
        first = parts[0] if path.startswith("~") else "/" + parts[0]
        path = first + "/…/" + "/".join(parts[-4:])
    venv = os.environ.get("VIRTUAL_ENV")
    venv_part = "(%s)─" % os.path.basename(venv.rstrip("/")) if venv else ""
    line = "\x1b[34m" if root else "\x1b[32m"
    name = "\x1b[31m" if root else "\x1b[34m"
    sign = "\x1b[31m#" if root else "\x1b[34m$"
    bold, unbold, default = "\x1b[1m", "\x1b[22m", "\x1b[39m"
    l1 = ("%s┌──%s(%s%s%s%s%s%s%s)-[%s%s%s%s%s]%s"
          % (line, venv_part, bold, name, user, glyph, host, unbold, line,
             bold, default, path, unbold, line, default))
    l2 = "%s└─%s%s%s%s " % (line, bold, sign, unbold, default)
    return l1, l2


def kill_group(pid):
    """Stop a command and everything it started. Returns its wait status if reaped."""
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
        end = time.time() + wait
        while time.time() < end:
            try:
                done, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return None
            if done:
                return status
            time.sleep(0.1)
    return None


def run_pty(text, env, cols, rows, timeout, sink):
    """Run one command under bash in its own pseudo terminal and stream its
    output to sink. Returns (exit code, timed out)."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass
        try:
            os.execvpe("bash", ["bash", "--noprofile", "--norc", "-c", text], env)
        finally:
            os._exit(127)
    start = time.time()
    timed_out = False
    status = None
    while True:
        if not timed_out and time.time() - start > timeout:
            timed_out = True
            reaped = kill_group(pid)
            if reaped is not None:
                status = reaped
            sink(b"\r\n[stopped by the evidence tool after %d seconds]\r\n" % timeout)
        try:
            ready, _, _ = select.select([fd], [], [], 0.2)
        except InterruptedError:
            continue
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if not data:
                break
            sink(data)
            continue
        if status is None:
            try:
                done, st = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                done, st = pid, 0
            if done:
                status = st
                end = time.time() + 0.5
                while time.time() < end:
                    ready, _, _ = select.select([fd], [], [], 0.1)
                    if not ready:
                        break
                    try:
                        data = os.read(fd, 65536)
                    except OSError:
                        data = b""
                    if not data:
                        break
                    sink(data)
                break
    if status is None:
        try:
            _, status = os.waitpid(pid, 0)
        except ChildProcessError:
            status = 0
    try:
        os.close(fd)
    except OSError:
        pass
    if timed_out:
        return 124, True
    return os.waitstatus_to_exitcode(status), False


def stamp(moment, seconds=True):
    """'26 Oct 2026 13:05:12 IST', or the UTC offset when the zone has no short name."""
    zone = moment.strftime("%Z")
    if not re.fullmatch(r"[A-Z]{2,5}", zone or ""):
        off = moment.strftime("%z")
        zone = "UTC%s:%s" % (off[:3], off[3:]) if off else ""
    return (moment.strftime("%d %b %Y %H:%M:%S" if seconds else "%d %b %Y %H:%M") + " " + zone).strip()


def run_session(cmds, prompt, env, cols, rows, sink):
    l1, l2 = prompt
    results = []
    for cmd in cmds:
        sink(("%s\r\n%s%s\r\n" % (l1, l2, cmd["text"])).encode("utf-8"))
        started = dt.datetime.now().astimezone()
        t0 = time.time()
        code, timed_out = run_pty(cmd["text"], env, cols, rows, cmd["timeout"], sink)
        results.append({"exit": code, "timed_out": timed_out,
                        "started": stamp(started),
                        "seconds": round(time.time() - t0, 1)})
    sink(("%s\r\n%s" % (l1, l2)).encode("utf-8"))
    return results


def session_child(spec_path):
    """Runs inside the xterm window."""
    with open(spec_path) as fh:
        spec = json.load(fh)
    log = open(spec["log"], "ab", buffering=0)

    def sink(data):
        try:
            os.write(1, data)
        except OSError:
            pass
        log.write(data)

    try:
        cols, rows = spec["cols"], spec["rows"]
        try:
            rows, cols = struct.unpack("HHHH", fcntl.ioctl(1, termios.TIOCGWINSZ, b"\0" * 8))[:2]
        except OSError:
            pass
        payload = {"results": run_session(spec["cmds"], spec["prompt"], os.environ.copy(), cols, rows, sink)}
    except Exception as exc:  # reported back to the controller
        payload = {"error": repr(exc)}
    tmp = spec["result"] + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh)
    os.replace(tmp, spec["result"])
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    signal.signal(signal.SIGHUP, lambda *_: os._exit(0))
    while True:
        time.sleep(60)


# ---------------------------------------------------------------------------
# Screenshot engines
# ---------------------------------------------------------------------------
BG = (12, 12, 12)
FG = (204, 204, 204)
PALETTE = ["#0C0C0C", "#C50F1F", "#13A10E", "#C19C00", "#0037DA", "#881798", "#3A96DD", "#CCCCCC",
           "#767676", "#E74856", "#16C60C", "#F9F1A5", "#3B78FF", "#B4009E", "#61D6D6", "#F2F2F2"]
BORDER = 12
DEJAVU = ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
          "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
          "/usr/share/fonts/dejavu/DejaVuSansMono.ttf"]


class EngineError(Exception):
    pass


def hex_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def font_with(charset_hex):
    if not shutil.which("fc-list"):
        return None
    try:
        out = subprocess.run(["fc-list", ":charset=%s" % charset_hex, "file"], capture_output=True,
                             text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    files = [ln.split(":")[0].strip() for ln in out.splitlines() if ln.strip()]
    files = [f for f in files if f.lower().endswith((".ttf", ".otf", ".ttc"))]
    return sorted(files, key=lambda f: ("mono" not in f.lower(), len(f)))[0] if files else None


def paginate(img, cw, ch, used_rows, used_cols, page_lines, min_cols):
    """Cut a terminal image into report sized pages on line boundaries."""
    from PIL import Image
    width = BORDER * 2 + max(used_cols, min_cols) * cw
    width = min(width, img.width)
    used_rows = max(used_rows, 1)
    pages = []
    for start in range(0, used_rows, page_lines):
        end = min(start + page_lines, used_rows)
        region = img.crop((0, BORDER + start * ch, width, BORDER + end * ch))
        page = Image.new("RGB", (width, region.height + 2 * BORDER), BG)
        page.paste(region, (0, BORDER))
        pages.append(page)
    return pages


class XtermEngine:
    name = "xterm"
    description = "real xterm window on a private Xvfb display, captured as shown"

    def __init__(self, opts, workdir):
        self.opts = opts
        self.workdir = workdir
        self.xvfb = None
        self.display = None
        self.grab_with = None
        self.font_size = opts.font_size
        self.rows = opts.max_lines
        self.cols = opts.cols
        self._start()

    @staticmethod
    def available():
        missing = [t for t in ("Xvfb", "xterm") if not shutil.which(t)]
        try:
            from PIL import features
            xcb = features.check_feature("xcb")
        except Exception:
            xcb = False
        if not xcb and not shutil.which("import"):
            missing.append("Pillow with XCB support or ImageMagick (import)")
        return missing

    def _start(self):
        x11 = "/tmp/.X11-unix"
        if not os.path.isdir(x11):
            try:
                os.makedirs(x11, mode=0o1777, exist_ok=True)
                os.chmod(x11, 0o1777)
            except OSError:
                pass
        width = self.cols * self.font_size + 200
        height = self.rows * self.font_size * 2 + 200
        log_path = os.path.join(self.workdir, "xvfb.log")
        # Display :93 and up, so the user's own display (:0 on WSLg or a desktop) is
        # never touched. The second variant listens on the abstract socket only, for
        # systems where /tmp/.X11-unix is read only (WSLg).
        for number in range(93, 113):
            for extra in ([], ["-nolisten", "unix"]):
                rfd, wfd = os.pipe()
                with open(log_path, "a") as log:
                    proc = subprocess.Popen(
                        ["Xvfb", ":%d" % number, "-displayfd", str(wfd), "-screen", "0",
                         "%dx%dx24" % (width, height), "-dpi", "96", "-nolisten", "tcp", "-wr"] + extra,
                        pass_fds=(wfd,), stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
                os.close(wfd)
                ready, _, _ = select.select([rfd], [], [], 15)
                reply = os.read(rfd, 64).decode().strip() if ready else ""
                os.close(rfd)
                if reply:
                    self.xvfb = proc
                    self.display = ":" + reply
                    break
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=5)
                except Exception:
                    pass
            if self.display:
                break
        if not self.display:
            raise EngineError("Xvfb did not start; see %s" % log_path)
        try:
            from PIL import features, ImageGrab
            if features.check_feature("xcb"):
                ImageGrab.grab(xdisplay=self.display)
                self.grab_with = "pillow"
        except Exception:
            self.grab_with = None
        if not self.grab_with and shutil.which("import"):
            self.grab_with = "import"
        if not self.grab_with:
            self.close()
            raise EngineError("cannot capture the virtual display (no Pillow XCB support and no ImageMagick)")

    def _grab(self):
        from PIL import Image, ImageGrab
        if self.grab_with == "pillow":
            return ImageGrab.grab(xdisplay=self.display).convert("RGB")
        path = os.path.join(self.workdir, "grab.png")
        subprocess.run(["import", "-display", self.display, "-window", "root", path],
                       check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with Image.open(path) as im:
            return im.convert("RGB")

    def shoot(self, cmds, prompt, env, log_path):
        from PIL import Image, ImageChops
        tag = "%d" % (time.time() * 1000)
        spec_path = os.path.join(self.workdir, "spec_%s.json" % tag)
        result_path = os.path.join(self.workdir, "result_%s.json" % tag)
        open(log_path, "wb").close()
        with open(spec_path, "w") as fh:
            json.dump({"cmds": cmds, "prompt": prompt, "cols": self.cols,
                       "rows": self.rows, "log": log_path, "result": result_path}, fh)
        args = ["xterm", "-display", self.display, "-geometry", "%dx%d+0+0" % (self.cols, self.rows),
                "-fa", "DejaVu Sans Mono", "-fs", str(self.font_size), "-bg", "#0C0C0C", "-fg", "#CCCCCC",
                "-cr", "#CCCCCC", "+sb", "-b", str(BORDER), "-bw", "0", "-u8", "-T", "evidence",
                "-xrm", "XTerm*boldColors: true", "-xrm", "XTerm*allowTitleOps: false"]
        for i, colour in enumerate(PALETTE):
            args += ["-xrm", "XTerm*color%d: %s" % (i, colour)]
        args += ["-e", sys.executable, os.path.abspath(__file__), "--_session", spec_path]
        env = dict(env)
        env["DISPLAY"] = self.display
        env.pop("WAYLAND_DISPLAY", None)
        if utf8_locale():
            env["LC_ALL"] = utf8_locale()
        with open(os.path.join(self.workdir, "xterm.log"), "a") as xlog:
            term = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=xlog,
                                    start_new_session=True)
        limit = time.time() + sum(c["timeout"] for c in cmds) + 60
        try:
            while not os.path.exists(result_path):
                if term.poll() is not None:
                    raise EngineError("xterm closed before the session finished (see xterm.log)")
                if time.time() > limit:
                    raise EngineError("session did not finish in time")
                time.sleep(0.2)
            time.sleep(0.8)
            screen = self._grab()
        finally:
            try:
                os.killpg(term.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                term.wait(timeout=5)
            except subprocess.TimeoutExpired:
                term.kill()
        with open(result_path) as fh:
            payload = json.load(fh)
        if "error" in payload:
            raise EngineError("session failed inside xterm: %s" % payload["error"])
        white = Image.new("RGB", screen.size, (255, 255, 255))
        box = ImageChops.difference(screen, white).convert("L").point(lambda v: 255 if v > 8 else 0).getbbox()
        if not box:
            raise EngineError("the xterm window was not found on the virtual display")
        win = screen.crop(box)
        cw = (win.width - 2 * BORDER) / float(self.cols)
        ch = (win.height - 2 * BORDER) / float(self.rows)
        if abs(cw - round(cw)) > 0.01 or abs(ch - round(ch)) > 0.01:
            raise EngineError("unexpected xterm window size %dx%d" % win.size)
        cw, ch = int(round(cw)), int(round(ch))
        bgimg = Image.new("RGB", win.size, BG)
        content = ImageChops.difference(win, bgimg).convert("L").point(lambda v: 255 if v > 30 else 0).getbbox()
        if content:
            used_rows = -(-(content[3] - BORDER) // ch)
            used_cols = -(-(content[2] - BORDER) // cw)
        else:
            used_rows, used_cols = 1, 1
        pages = paginate(win, cw, ch, used_rows, used_cols, self.opts.page_lines, self.opts.min_cols)
        return pages, payload["results"]

    def close(self):
        if self.xvfb and self.xvfb.poll() is None:
            try:
                os.killpg(self.xvfb.pid, signal.SIGTERM)
                self.xvfb.wait(timeout=5)
            except Exception:
                try:
                    self.xvfb.kill()
                except Exception:
                    pass
        self.xvfb = None


class RenderEngine:
    name = "render"
    description = "pseudo terminal session drawn by the pyte terminal emulator"

    def __init__(self, opts, workdir):
        try:
            import pyte  # noqa: F401
        except ImportError:
            raise EngineError("pyte is not installed (pip install pyte)")
        from PIL import ImageFont
        self.opts = opts
        self.cols = opts.cols
        self.rows = 3000
        px = int(round(opts.font_size * 96 / 72.0))
        regular = next((p for p in DEJAVU if os.path.exists(p)), None) or font_with("41")
        if not regular:
            raise EngineError("no monospace font found (sudo apt install fonts-dejavu-core)")
        bold = regular.replace("SansMono.ttf", "SansMono-Bold.ttf")
        self.font = ImageFont.truetype(regular, px)
        self.bold = ImageFont.truetype(bold, px) if os.path.exists(bold) else self.font
        wide = font_with("327f")
        self.wide = ImageFont.truetype(wide, px) if wide else None
        self.cw = int(round(self.font.getlength("M")))
        ascent, descent = self.font.getmetrics()
        self.ch = ascent + descent + 1

    @staticmethod
    def available():
        try:
            import pyte  # noqa: F401
            return []
        except ImportError:
            return ["pyte (pip install pyte)"]

    def colour(self, value, bold, is_fg):
        if value == "default":
            if is_fg:
                return hex_rgb(PALETTE[15]) if bold else FG
            return BG
        names = {"black": 0, "red": 1, "green": 2, "brown": 3, "yellow": 3, "blue": 4,
                 "magenta": 5, "cyan": 6, "white": 7}
        if value in names:
            idx = names[value] + (8 if bold and is_fg else 0)
            return hex_rgb(PALETTE[idx])
        if value.startswith("bright") and value[6:] in names:
            return hex_rgb(PALETTE[names[value[6:]] + 8])
        if re.fullmatch(r"[0-9a-fA-F]{6}", value):
            return hex_rgb(value)
        return FG if is_fg else BG

    def shoot(self, cmds, prompt, env, log_path):
        import pyte
        from PIL import Image, ImageDraw
        screen = pyte.Screen(self.cols, self.rows)
        stream = pyte.ByteStream(screen)
        log = open(log_path, "wb")

        def sink(data):
            log.write(data)
            stream.feed(data)

        env = dict(env)
        env["TERM"] = "xterm"
        try:
            results = run_session(cmds, prompt, env, self.cols, 200, sink)
        finally:
            log.close()
        used_rows = screen.cursor.y + 1
        used_cols = 1
        for y in range(used_rows):
            line = screen.buffer[y]
            for x in range(self.cols - 1, -1, -1):
                if line[x].data not in (" ", ""):
                    used_cols = max(used_cols, x + 1)
                    break
        used_cols = max(used_cols, screen.cursor.x + 1)
        img = Image.new("RGB", (BORDER * 2 + self.cols * self.cw, BORDER * 2 + used_rows * self.ch), BG)
        draw = ImageDraw.Draw(img)
        for y in range(used_rows):
            line = screen.buffer[y]
            for x in range(self.cols):
                char = line[x]
                if char.data == "":
                    continue
                fg = self.colour(char.fg, char.bold, True)
                bg = self.colour(char.bg, False, False)
                if char.reverse:
                    fg, bg = bg, fg
                px, py = BORDER + x * self.cw, BORDER + y * self.ch
                width = self.cw * (2 if ord(char.data[0]) > 0x2fff else 1)
                if bg != BG:
                    draw.rectangle([px, py, px + width - 1, py + self.ch - 1], fill=bg)
                if char.data == " ":
                    continue
                font = self.bold if char.bold else self.font
                if ord(char.data[0]) > 0x2fff:
                    if self.wide:
                        draw.text((px, py), char.data, font=self.wide, fill=fg)
                    else:
                        draw.text((px, py), "@", font=font, fill=fg)
                else:
                    draw.text((px, py), char.data, font=font, fill=fg)
        cx, cy = BORDER + screen.cursor.x * self.cw, BORDER + screen.cursor.y * self.ch
        draw.rectangle([cx, cy, cx + self.cw - 1, cy + self.ch - 1], outline=FG)
        pages = paginate(img, self.cw, self.ch, used_rows, used_cols, self.opts.page_lines, self.opts.min_cols)
        return pages, results

    def close(self):
        pass


_LOCALE = []


def utf8_locale():
    if _LOCALE:
        return _LOCALE[0]
    _LOCALE.append(_find_utf8_locale())
    return _LOCALE[0]


def _find_utf8_locale():
    try:
        out = subprocess.run(["locale", "-a"], capture_output=True, text=True, timeout=10).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return None
    for name in ("C.UTF-8", "C.utf8", "en_US.UTF-8", "en_US.utf8"):
        if name in out:
            return name
    return None


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
def command_env(opts):
    """The gcloud and kubectl settings every command in the evidence inherits,
    so the commands on screen stay readable and still target one project."""
    env = {
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "CLOUDSDK_CORE_PROJECT": opts.project,
        "USE_GKE_GCLOUD_AUTH_PLUGIN": "True",
        "KUBECONFIG": opts.kubeconfig,
    }
    if opts.account:
        env["CLOUDSDK_CORE_ACCOUNT"] = opts.account
    if opts.configuration:
        env["CLOUDSDK_ACTIVE_CONFIG_NAME"] = opts.configuration
    if opts.impersonate_service_account:
        env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] = opts.impersonate_service_account
    return env


def base_env(opts):
    env = os.environ.copy()
    env.update(command_env(opts))
    return env


def gcloud_out(args, env, timeout=120):
    """Run a gcloud read and return (stdout, error message)."""
    try:
        proc = subprocess.run(["gcloud"] + args, env=env, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timed out after %ds" % timeout
    except OSError as exc:
        return None, str(exc)
    if proc.returncode != 0:
        lines = [ln.strip() for ln in (proc.stderr or proc.stdout).splitlines() if ln.strip()]
        detail = next((ln for ln in lines if "ERROR" in ln or "denied" in ln or "permission" in ln),
                      lines[-1] if lines else "exit code %d" % proc.returncode)
        return None, re.sub(r"^ERROR:\s*", "", detail)[:300]
    return proc.stdout, None


def active_account(env):
    out, err = gcloud_out(["config", "list", "--format=value(core.account)"], env)
    if err:
        return None, err
    account = (out or "").strip()
    return account or None, None if account else "no active gcloud account"


# Cheap reads used to prove the identity can see the project. The first one
# that succeeds is enough, because a read only role may be missing any one of
# these permissions while still granting the rest.
ACCESS_PROBES = [
    ("project metadata", ["projects", "describe", "--format=value(projectId)"]),
    ("enabled services", ["services", "list", "--enabled", "--limit=1", "--format=value(config.name)"]),
    ("GKE clusters", ["container", "clusters", "list", "--limit=1", "--format=value(name)"]),
    ("VPC networks", ["compute", "networks", "list", "--limit=1", "--format=value(name)"]),
    ("Cloud SQL instances", ["sql", "instances", "list", "--limit=1", "--format=value(name)"]),
]


def verify_access(opts, env):
    """(account, [probes that worked], [probes that were refused])."""
    account, err = active_account(env)
    if err:
        return None, [], [("gcloud account", err)]
    works, refused = [], []
    for label, args in ACCESS_PROBES:
        if args[0] == "projects":
            args = args[:2] + [opts.project] + args[2:]
        _out, perr = gcloud_out(args, env)
        if perr:
            refused.append((label, perr))
        else:
            works.append(label)
    return account, works, refused


def resolve_target(host, cache):
    """A hostname is contacted only when every address behind it right now is in
    scope, so a name re-pointed at a third party is never scanned."""
    if host in cache:
        return cache[host]
    if IPV4.fullmatch(host):
        ok = host in IN_SCOPE_IPS
        cache[host] = (ok, "declared in scope" if ok else "not an in scope address")
        return cache[host]
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        cache[host] = (False, "does not resolve (%s)" % (exc.strerror or "lookup failed"))
        return cache[host]
    found = sorted({info[4][0] for info in infos})
    outside = [ip for ip in found if ip not in IN_SCOPE_IPS]
    if outside:
        cache[host] = (False, "resolves to %s, which is outside the scope" % ", ".join(outside))
    else:
        cache[host] = (True, "resolves to %s" % ", ".join(found))
    return cache[host]


def targets_ready(cmd, cache):
    """(runnable, notes) for one network command."""
    notes = []
    for host in sorted(net_hosts(cmd["text"])):
        ok, why = resolve_target(host, cache)
        if not ok:
            notes.append("%s %s" % (host, why))
    return not notes, notes


def kube_setup(opts, env):
    """Write the run private kubeconfig and find out whether the API server
    answers from here. A private control plane is expected not to."""
    args = ["container", "clusters", "get-credentials", opts.cluster,
            "--project", opts.project, "--location", opts.region]
    _out, err = gcloud_out(args, env, timeout=180)
    if err:
        return False, "cluster credentials could not be fetched: %s" % err
    try:
        proc = subprocess.run(["kubectl", "version", "--request-timeout=25s", "-o", "json"],
                              env=env, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "kubectl did not run: %s" % exc
    if proc.returncode != 0 or "serverVersion" not in (proc.stdout or ""):
        detail = " ".join((proc.stderr or proc.stdout or "").split())[:240]
        return False, ("the control plane did not answer from this network, which is what a "
                       "private endpoint looks like: %s" % detail)
    try:
        server = json.loads(proc.stdout)["serverVersion"]["gitVersion"]
    except (ValueError, KeyError):
        server = "reachable"
    return True, "control plane answered, server version %s" % server


def tool_version(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out = (proc.stdout or proc.stderr).strip().splitlines()
        return out[0] if out else "found"
    except (OSError, subprocess.SubprocessError):
        return None


def check(opts):
    ok = True
    print("Augnito GCP assessment evidence %s: environment check\n" % VERSION)
    rows = [("python", sys.version.split()[0], True, "")]
    try:
        import PIL
        rows.append(("Pillow", PIL.__version__, True, ""))
    except ImportError:
        rows.append(("Pillow", "missing", False, "pip install -r requirements.txt"))
        ok = False
    gv = tool_version(["gcloud", "--version"]) if shutil.which("gcloud") else None
    rows.append(("gcloud", gv or "missing", bool(gv),
                 "" if gv else "install the Google Cloud CLI"))
    ok = ok and bool(gv)
    kv = tool_version(["kubectl", "version", "--client=true", "-o", "yaml"]) if shutil.which("kubectl") else None
    rows.append(("kubectl", "found" if kv else "missing", bool(kv),
                 "" if kv else "gcloud components install kubectl (in cluster test cases are skipped without it)"))
    plug = shutil.which("gke-gcloud-auth-plugin")
    rows.append(("gke auth plugin", "found" if plug else "missing", bool(plug),
                 "" if plug else "gcloud components install gke-gcloud-auth-plugin"))
    for tool, fix in (("nmap", "sudo apt install nmap"), ("curl", "sudo apt install curl"),
                      ("openssl", "sudo apt install openssl"), ("dig", "sudo apt install dnsutils")):
        found = shutil.which(tool)
        rows.append((tool, "found" if found else "missing", bool(found),
                     "" if found else "%s (network test cases are skipped without it)" % fix))
    xmiss = XtermEngine.available()
    if not xmiss:
        workdir = tempfile.mkdtemp(prefix="gcpev_check_")
        try:
            probe = XtermEngine(opts, workdir)
            probe.close()
        except EngineError as exc:
            xmiss = ["virtual display did not start (%s)" % exc]
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    rows.append(("xterm engine", "ready (real screenshots)" if not xmiss else "not usable: " + ", ".join(xmiss),
                 not xmiss, "" if not xmiss else "sudo apt install xvfb xterm imagemagick fonts-dejavu-core"))
    rmiss = RenderEngine.available()
    rows.append(("render engine", "ready" if not rmiss else "missing: " + ", ".join(rmiss), not rmiss,
                 "" if not rmiss else "pip install -r requirements.txt"))
    glyph = font_with("327f")
    rows.append(("prompt glyph font", glyph or "none (prompt shows @ instead)", bool(glyph),
                 "" if glyph else "sudo apt install fonts-nanum"))
    for name, value, good, fix in rows:
        print("  %-18s %-4s %s%s" % (name, "OK" if good else "--", value,
                                     ("\n" + " " * 26 + "fix: " + fix) if fix else ""))
    if xmiss and rmiss:
        ok = False
    print()
    if not gv:
        return 1

    env = base_env(opts)
    account, works, refused = verify_access(opts, env)
    if not account:
        print("Access: FAILED\n  %s\n" % (refused[0][1] if refused else "no active account"))
        explain_credentials(opts)
        return 1
    print("Identity")
    print("  account  %s" % account)
    print("  project  %s" % opts.project)
    if opts.impersonate_service_account:
        print("  acting as %s" % opts.impersonate_service_account)
    print("\nRead access to the project")
    for label in works:
        print("  OK   %s" % label)
    for label, err in refused:
        print("  --   %-22s %s" % (label, err))
    if not works:
        print("\nAccess: FAILED. This identity cannot read anything in %s." % opts.project)
        explain_credentials(opts)
        return 1
    print("\n%d of %d reads succeeded. Checks that need a permission this role does not"
          % (len(works), len(works) + len(refused)))
    print("have will record the refusal, which is itself a documented limit of the test.")

    print("\nIn cluster access")
    if not shutil.which("kubectl"):
        print("  --   kubectl is not installed, test cases 8 to 15 will be skipped")
    else:
        ready, why = kube_setup(opts, env)
        print("  %s   %s" % ("OK " if ready else "-- ", why))

    print("\nNetwork targets (resolved now)")
    cache = {}
    for target, desc in SCAN_TARGETS.items():
        good, why = resolve_target(target, cache)
        print("  %-32s %-4s %s" % (target, "yes" if good else "NO", why))
        if not good:
            print("  %34s %s" % ("", desc))
    print("\nReady." if ok else "\nFix the items marked -- first.")
    return 0 if ok else 1


def explain_credentials(opts):
    print("How to give the tool the right identity:")
    print("  1. gcloud auth login                     sign in with the organisation account")
    print("     that was granted read only access to %s." % opts.project)
    print("  2. python3 %s --check" % os.path.basename(__file__))
    print("  3. If you keep several accounts signed in, name the one to use:")
    print("       --account you@your-org.com")
    print("     or point at a saved configuration:  --configuration augnito-ksa")
    print("  4. If the access was granted to a service account you may impersonate:")
    print("       --impersonate-service-account reader@%s.iam.gserviceaccount.com" % opts.project)
    print("  5. gcloud auth list                      shows every account signed in now.")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]|\x1b[=>]")
# A 403 is a documented limit of the granted role, not a failed command.
DENIED = re.compile(r"does not have permission|Required .* permission|PERMISSION_DENIED|"
                    r"not authorized|caller does not have|permission denied|"
                    r"code=403|HTTPError 403|status: 403|403 Forbidden", re.I)


def plain(data):
    text = data.decode("utf-8", "replace")
    return ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "")


def stamp_pages(pages, label):
    from PIL import Image, ImageDraw, ImageFont
    font_path = next((p for p in DEJAVU if os.path.exists(p)), None)
    font = ImageFont.truetype(font_path, 14) if font_path else ImageFont.load_default()
    out = []
    for i, page in enumerate(pages, 1):
        text = label + (("  |  part %d of %d" % (i, len(pages))) if len(pages) > 1 else "")
        strip = 28
        im = Image.new("RGB", (page.width, page.height + strip), (40, 40, 40))
        im.paste(page, (0, 0))
        ImageDraw.Draw(im).text((BORDER, page.height + 6), text, font=font, fill=(235, 200, 120))
        out.append(im)
    return out


PROMPT_TOP = "\u250c\u2500\u2500"
PROMPT_RUN = "\u2514\u2500"


def split_capture(text, cmds):
    """One (lines, denied) pair per command in the screenshot.

    The two line prompt delimits each command, so the text splits cleanly on it.
    gcloud reports a refusal as a block -- an ERROR: line followed by a help
    token and a YAML violations section -- so a block is judged as a whole
    rather than line by line, and a refusal anywhere in it marks the command.
    """
    echoed = [c["text"].strip() for c in cmds]
    blocks, current, started = [], [], False
    for line in text.splitlines():
        if line.lstrip().startswith(PROMPT_TOP):
            if started:
                blocks.append(current)
            current, started = [], True
            continue
        if started:
            current.append(line)
    if started:
        blocks.append(current)

    out = []
    for block in blocks:
        body = []
        for line in block:
            stripped = line.strip()
            if not stripped or stripped.startswith(PROMPT_RUN):
                continue
            if stripped in echoed or any(stripped.endswith(e) for e in echoed):
                continue
            body.append(stripped)
        out.append((body, any(DENIED.search(line) for line in body)))
    # The run ends on a bare prompt, so drop blocks past the last command.
    return out[:len(cmds)] + [([], False)] * max(0, len(cmds) - len(out))


# A route is a URL path and nothing else. Shell metacharacters are refused
# outright so a mistyped value cannot reshape the command it lands in.
APP_PATH_OK = re.compile(r"^/[A-Za-z0-9/._~%-]{0,200}$")


def match_endpoint(key, hosts):
    """One in scope endpoint, named in full, by a unique part of its name, or
    by its number in the scope document."""
    if key.isdigit():
        index = int(key)
        if 1 <= index <= len(hosts):
            return hosts[index - 1]
        sys.exit("--app-path: there is no endpoint %s, there are %d" % (key, len(hosts)))
    if key in hosts:
        return key
    matches = [h for h in hosts if key in h]
    listing = "\n  ".join("%d  %s" % (i, h) for i, h in enumerate(hosts, 1))
    if not matches:
        sys.exit("--app-path: %r does not name an in scope endpoint. They are:\n  %s"
                 % (key, listing))
    if len(matches) > 1:
        sys.exit("--app-path: %r matches more than one endpoint:\n  %s\n"
                 "Use the full name or its number:\n  %s"
                 % (key, "\n  ".join(matches), listing))
    return matches[0]


def resolve_app_paths(values, hosts):
    """The route each endpoint is tested on.

    A value is either a bare path, which becomes the route for every endpoint
    not named separately, or endpoint=path. Later values win, and a named
    endpoint always beats a bare default.
    """
    paths = dict.fromkeys(hosts, APP_PATH)
    named = {}
    for value in values or []:
        if "=" in value:
            key, _, path = value.partition("=")
            named[match_endpoint(key.strip(), hosts)] = path.strip()
        else:
            paths = dict.fromkeys(hosts, value.strip())
    paths.update(named)
    for host, path in paths.items():
        if not APP_PATH_OK.match(path):
            sys.exit("--app-path for %s: %r must start with / and hold only URL path "
                     "characters (letters, digits and / . _ ~ - %%)" % (host, path))
    return paths


def evidence_lines(text, cmds):
    """The lines a screenshot actually returned, with every refused command's
    output left out. An empty result means the check found nothing to assess,
    which the client asked to be recorded as a false."""
    return [line for body, denied in split_capture(text, cmds)
            if not denied for line in body]


def safe_folder(title):
    return re.sub(r'[<>:"/\\|?*]', "_", title).strip().rstrip(".")


def parse_only(spec):
    numbers = {n for n, _t, _s in TESTS}
    if not spec:
        return sorted(numbers)
    chosen = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            chosen.update(range(int(a), int(b) + 1))
        else:
            chosen.add(int(part))
    bad = sorted(chosen - numbers)
    if bad:
        sys.exit("Unknown test case numbers: %s (valid %d to %d)"
                 % (", ".join(map(str, bad)), min(numbers), max(numbers)))
    return sorted(chosen)


def app_route_lines(paths):
    width = max(len(h) for h in paths)
    return ["  %-*s  %s" % (width, h, paths[h]) for h in HOSTS]


def dry_run(selected, opts):
    if any(c["route"] for num, _t, shots in TESTS if num in selected
           for s in shots for c in s["cmds"]):
        print("Application routes under test")
        print("\n".join(app_route_lines(opts.app_paths)) + "\n")
    shots = [(0, "Session", [SESSION])] + [t for t in TESTS if t[0] in selected]
    for num, title, items in shots:
        print("[%s] %s" % ("--" if num == 0 else "%2d" % num, title))
        for i, shot in enumerate(items, 1):
            print("   screenshot %d: %s" % (i, shot["title"]))
            for cmd in shot["cmds"]:
                tags = []
                if cmd["net"]:
                    why = ""
                    if opts.no_scan:
                        why = ", skipped with --no-scan"
                    elif cmd["net"] == "app" and opts.no_app_layer:
                        why = ", skipped with --no-app-layer"
                    tags.append("%s network test%s" % (cmd["net"], why))
                if cmd["dynamic"]:
                    tags.append("address read from the resource's own record at run time")
                if cmd["kube"]:
                    tags.append("needs the cluster API%s" % (", skipped with --no-kubectl" if opts.no_kubectl else ""))
                if cmd["setup"]:
                    tags.append("writes the run private kubeconfig")
                print("      $ %s%s" % (cmd["text"], ("   [%s]" % "; ".join(tags)) if tags else ""))
    print("\nEvery command passed the read only and scope checks.")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Capture read only penetration test evidence for the Augnito GCP environment.")
    ap.add_argument("--only", help="test case numbers, for example 2,16,25 or 1-9")
    ap.add_argument("--no-scan", action="store_true", help="skip nmap, curl and openssl, run the GCP checks only")
    ap.add_argument("--no-kubectl", action="store_true", help="skip the in cluster test cases (8 to 15)")
    ap.add_argument("--no-app-layer", action="store_true",
                    help="skip the application layer test cases (43 to 48)")
    ap.add_argument("--app-path", action="append", metavar="[ENDPOINT=]PATH",
                    help="the route test cases 44 to 48 exercise (default %s). Give it once "
                         "for every endpoint, or repeat it as ENDPOINT=PATH to use a different "
                         "route per endpoint, where ENDPOINT is the hostname, a unique part of "
                         "it, or its number: --app-path apps=/ --app-path ambient=/v1/ambient"
                         % APP_PATH)
    ap.add_argument("--account", help="gcloud account to use, for example you@your-org.com")
    ap.add_argument("--configuration", help="gcloud configuration to use, for example augnito-ksa")
    ap.add_argument("--impersonate-service-account", help="service account to act as")
    ap.add_argument("--project", default=PROJECT, help="expected project ID (default %(default)s)")
    ap.add_argument("--cluster", default=CLUSTER, help="GKE cluster (default %(default)s)")
    ap.add_argument("--region", default=REGION, help="region (default %(default)s)")
    ap.add_argument("--force", action="store_true",
                    help="capture even when no read succeeded, to document that access was not granted")
    ap.add_argument("--engine", choices=("auto", "xterm", "render"), default="auto",
                    help="screenshot engine (default auto: xterm when available)")
    ap.add_argument("--out", help="output folder (default GCP_Assessment_Evidence_<timestamp>)")
    ap.add_argument("--stamp", action="store_true", help="add a caption strip with time and test case under each image")
    ap.add_argument("--font-size", type=int, default=12, help="terminal font size in points (default 12)")
    ap.add_argument("--cols", type=int, default=150, help="terminal width in columns (default 150)")
    ap.add_argument("--min-cols", type=int, default=100, help="narrowest image width in columns (default 100)")
    ap.add_argument("--page-lines", type=int, default=60, help="lines per image before splitting (default 60)")
    ap.add_argument("--max-lines", type=int, default=250, help="xterm height in lines (default 250)")
    ap.add_argument("--check", action="store_true", help="check tools and access, then exit")
    ap.add_argument("--dry-run", action="store_true", help="print every command and exit")
    ap.add_argument("--no-zip", action="store_true", help="do not zip the evidence folder")
    ap.add_argument("--_session", help=argparse.SUPPRESS)
    opts = ap.parse_args(argv)

    if opts._session:
        session_child(opts._session)
        return 0

    opts.app_layer = not opts.no_app_layer
    opts.app_paths = resolve_app_paths(opts.app_path, HOSTS)
    for _num, _title, shots in TESTS:
        for shot in shots:
            for cmd in shot["cmds"]:
                route = opts.app_paths.get(cmd["target"])
                if cmd["route"] and route and route != cmd["route"]:
                    cmd["text"] = cmd["text"].replace(cmd["route"], route)
                    cmd["route"] = route
    guard_all()
    selected = parse_only(opts.only)
    if opts.dry_run:
        opts.kubeconfig = "<run private kubeconfig>"
        dry_run(selected, opts)
        return 0

    workdir = tempfile.mkdtemp(prefix="gcpev_")
    # Never touch the tester's own ~/.kube/config.
    opts.kubeconfig = os.path.join(workdir, "kubeconfig")
    try:
        return capture(opts, selected, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def capture(opts, selected, workdir):
    if opts.check:
        return check(opts)
    try:
        import PIL  # noqa: F401
    except ImportError:
        sys.exit("Pillow is missing. Run: pip install -r requirements.txt")
    if not shutil.which("gcloud"):
        sys.exit("The Google Cloud CLI (gcloud) was not found.")

    env = base_env(opts)
    account, works, refused = verify_access(opts, env)
    if not account:
        print("Could not determine the active gcloud account.\n")
        explain_credentials(opts)
        return 2
    # The external and application layer test cases never call gcloud, so a
    # missing or delayed project grant must not cost the tester that phase.
    needs_gcloud = any("gcloud" in c["text"] for num, _t, shots in TESTS if num in selected
                       for s in shots for c in s["cmds"])
    if not works and needs_gcloud and not opts.force:
        print("Stopped: %s cannot read anything in project %s.\n" % (account, opts.project))
        for label, err in refused:
            print("  %-22s %s" % (label, err))
        print()
        explain_credentials(opts)
        print("\nThe selected test cases need project reads. Test cases 35 to 38 and 43 to 48")
        print("do not, so those can be captured now: --only 35-38,43-48")
        print("To capture the rest anyway, and document that access was not granted, add --force.")
        return 2
    if not works and not needs_gcloud:
        print("Note: this identity cannot read the project, but no selected test case "
              "needs a project read.\n")

    needs_kube = any(c["kube"] for num, _t, shots in TESTS if num in selected
                     for s in shots for c in s["cmds"])
    kube_ok = False
    if not needs_kube:
        kube_why = "not needed, no selected test case uses the cluster API"
    elif opts.no_kubectl:
        kube_why = "skipped with --no-kubectl"
    elif not shutil.which("kubectl"):
        kube_why = "kubectl is not installed"
    else:
        kube_ok, kube_why = kube_setup(opts, env)

    missing_net = [t for t in ("nmap", "curl", "openssl", "dig") if not shutil.which(t)]
    engine, errors = None, []
    if opts.engine in ("auto", "xterm"):
        miss = XtermEngine.available()
        if miss:
            errors.append("xterm engine unavailable: missing " + ", ".join(miss))
        else:
            try:
                engine = XtermEngine(opts, workdir)
            except EngineError as exc:
                errors.append("xterm engine failed to start: %s" % exc)
        if engine is None and opts.engine == "xterm":
            sys.exit("\n".join(errors) + "\nInstall: sudo apt install xvfb xterm imagemagick fonts-dejavu-core")
    if engine is None:
        try:
            engine = RenderEngine(opts, workdir)
        except EngineError as exc:
            sys.exit("\n".join(errors + ["render engine unavailable: %s" % exc]) +
                     "\nRun: sudo apt install xvfb xterm imagemagick fonts-dejavu-core   or   pip install pyte")
    for line in errors:
        print("Note: " + line + ", using the render engine")

    started = dt.datetime.now().astimezone()
    out_dir = os.path.abspath(opts.out or "GCP_Assessment_Evidence_%s" % started.strftime("%Y%m%d_%H%M"))
    os.makedirs(out_dir, exist_ok=True)
    prompt = kali_prompt(GLYPH if font_with("327f") else "@")
    dns_cache = {}
    index_rows, summary, unexpected, denied, skipped_all = [], {}, [], [], []
    # Per test case: "review" when it returned something to assess, "false" when
    # it returned nothing (the client asked for an empty getIamPolicy, and any
    # other empty read, to be recorded that way), "not run" when it was skipped.
    verdicts = {}
    interrupted = False

    def write_test_index(folder, num, title, lines):
        header = "Session details" if num == 0 else "Test case %d: %s" % (num, title)
        with open(os.path.join(folder, "_index.txt"), "w", encoding="utf-8") as fh:
            fh.write("%s\nGCP assessment evidence captured %s\nProject %s, region %s, identity %s\n\n"
                     % (header, stamp(started, seconds=False), opts.project, opts.region, account))
            fh.write("\n".join(lines))

    print("Identity %s on project %s (%d of %d read probes succeeded)"
          % (account, opts.project, len(works), len(works) + len(refused)))
    print("In cluster access: %s" % kube_why)
    if opts.app_layer and any(c["route"] for num, _t, shots in TESTS if num in selected
                              for s in shots for c in s["cmds"]):
        print("Application routes under test:")
        print("\n".join(app_route_lines(opts.app_paths)))
    print("Engine: %s, %s" % (engine.name, engine.description))
    print("Evidence folder: %s\n" % out_dir)

    plan = [(0, "_Session", [SESSION])] + [t for t in TESTS if t[0] in selected]
    try:
        for num, title, shots in plan:
            folder = os.path.join(out_dir, "_Session" if num == 0 else safe_folder(title))
            os.makedirs(folder, exist_ok=True)
            print("[%s] %s" % ("--" if num == 0 else "%2d" % num, "Session" if num == 0 else title))
            lines_out = []
            case_evidence, case_ran = 0, False
            if num:
                summary[num] = (title, 0)
            for i, shot in enumerate(shots, 1):
                base = "session -%d" % i if num == 0 else "TC-%d -%d" % (num, i)
                cmds, notes = [], []
                for cmd in shot["cmds"]:
                    if cmd["net"]:
                        if opts.no_scan:
                            notes.append("not run (--no-scan): %s" % cmd["text"])
                            continue
                        if cmd["net"] == "app" and not opts.app_layer:
                            notes.append("not run (--no-app-layer): %s" % cmd["text"])
                            continue
                        blocked = [t for t in NET_TOOLS[cmd["net"]] if t in missing_net
                                   and re.search(r"\b%s\b" % t, cmd["text"])]
                        if blocked:
                            notes.append("not run (%s not installed): %s" % (", ".join(blocked), cmd["text"]))
                            continue
                        # A dns lookup sends nothing to the target, and a dynamic
                        # target has no literal host to resolve ahead of time.
                        if cmd["net"] == "dns" or cmd["dynamic"]:
                            ready, why = True, []
                        else:
                            ready, why = targets_ready(cmd, dns_cache)
                        if not ready:
                            notes.append("not run, %s: %s" % ("; ".join(why), cmd["text"]))
                            continue
                    if cmd["kube"] and not kube_ok:
                        notes.append("not run, %s: %s" % (kube_why, cmd["text"]))
                        continue
                    cmds.append(cmd)
                skipped_all += ["test case %d: %s" % (num, n) for n in notes]
                if not cmds:
                    reasons = sorted({n.split(":")[0] for n in notes})
                    print("      %-18s skipped, %s" % (base, "; ".join(reasons)))
                    lines_out.append("%s  not captured\n  %s\n" % (base, "\n  ".join(notes)))
                    write_test_index(folder, num, title, lines_out)
                    continue
                guard_shot({"cmds": cmds}, base)
                log_path = os.path.join(folder, base + ".log")
                t0 = time.time()
                try:
                    pages, results = engine.shoot(cmds, prompt, env, log_path)
                except EngineError as exc:
                    if engine.name != "xterm":
                        raise
                    print("      xterm engine problem (%s), switching to the render engine" % exc)
                    engine.close()
                    engine = RenderEngine(opts, workdir)
                    pages, results = engine.shoot(cmds, prompt, env, log_path)
                with open(log_path, "rb") as fh:
                    raw = fh.read()
                os.remove(log_path)
                text = plain(raw)
                if opts.stamp:
                    pages = stamp_pages(pages, "%s  |  %s  |  project %s  |  %s"
                                        % (base, results[0]["started"], opts.project, shot["title"]))
                names = []
                for p, page in enumerate(pages, 1):
                    name = base + (" (%d of %d)" % (p, len(pages)) if len(pages) > 1 else "") + ".png"
                    page.save(os.path.join(folder, name))
                    names.append(name)
                if num:
                    summary[num] = (title, summary[num][1] + len(names))
                blocks = split_capture(text, cmds)
                was_denied = any(d for _body, d in blocks)
                if was_denied and num:
                    denied.append((num, base, title))
                case_ran = True
                case_evidence += sum(len(b) for b, d in blocks if not d)
                lines = []
                for (cmd, res), (_body, cmd_denied) in zip(zip(cmds, results), blocks):
                    expected = res["exit"] in cmd["ok"] and not res["timed_out"]
                    state = "exit %d%s" % (res["exit"], ", stopped at timeout" if res["timed_out"] else "")
                    if not expected:
                        unexpected.append((num, base, cmd["text"], state))
                    lines.append("  $ %s\n    %s, started %s, %.1fs%s"
                                 % (cmd["text"], state, res["started"], res["seconds"],
                                    "" if expected else "  <- check"))
                    index_rows.append([num, title if num else "Session", base, ";".join(names),
                                       shot["title"], cmd["text"], res["exit"],
                                       "yes" if expected else "no",
                                       "yes" if cmd_denied else "no", res["started"],
                                       res["seconds"], ""])
                with open(os.path.join(folder, base + ".txt"), "w", encoding="utf-8") as fh:
                    fh.write(text.rstrip() + "\n\n")
                    fh.write("# %s\n# captured with the %s engine\n" % (shot["title"], engine.name))
                    for cmd, res in zip(cmds, results):
                        fh.write("# exit %d, started %s, %.1fs: %s\n"
                                 % (res["exit"], res["started"], res["seconds"], cmd["text"]))
                lines_out.append("%s  %s\n%s%s\n" % (", ".join(names), shot["title"], "\n".join(lines),
                                                     ("\n  " + "\n  ".join(notes)) if notes else ""))
                write_test_index(folder, num, title, lines_out)
                print("      %-18s %d image%s, exit %s, %.0fs%s"
                      % (base, len(names), "" if len(names) == 1 else "s",
                         "/".join(str(r["exit"]) for r in results), time.time() - t0,
                         "  (permission denied in output)" if was_denied else ""))
            if num:
                verdicts[num] = ("not run" if not case_ran
                                 else "false" if case_evidence == 0 else "review")
                print("      %-18s result: %s" % ("", verdicts[num]))
    except KeyboardInterrupt:
        interrupted = True
        print("\nStopped by user.")
    finally:
        engine.close()
        for root, _dirs, files in os.walk(out_dir):
            for name in files:
                if name.endswith(".log"):
                    os.remove(os.path.join(root, name))

    with open(os.path.join(out_dir, "_index.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["test_case", "title", "screenshot", "images", "shows", "command",
                    "exit_code", "expected", "permission_denied", "started", "seconds",
                    "result"])
        for row in index_rows:
            row[-1] = verdicts.get(row[0], "")
        w.writerows(index_rows)

    total = sum(n for _t, n in summary.values())
    with open(os.path.join(out_dir, "_README.txt"), "w", encoding="utf-8") as fh:
        fh.write("Augnito GCP Cloud Penetration Test (%s): test case evidence\n\n" % ENVIRONMENT)
        fh.write("Captured   %s\n" % stamp(started, seconds=False))
        fh.write("Environment %s (client confirmed this is not production)\n" % ENVIRONMENT)
        fh.write("Project    %s (number %s)\nRegion     %s\n"
                 % (opts.project, PROJECT_NUMBER, opts.region))
        fh.write("Granted    %s (read only); test case 41 shows what it resolves to\n"
                 % GRANTED_ROLE)
        fh.write("Identity   %s\n" % account)
        if opts.impersonate_service_account:
            fh.write("Acting as  %s\n" % opts.impersonate_service_account)
        fh.write("Cluster    %s\nSQL        %s\nRegistry   %s\nVPC        %s / %s\n"
                 % (opts.cluster, SQL_INSTANCE, AR_REPO, VPC, SUBNET))
        fh.write("Endpoints  %s\n           %s\n" % (LB_IP, "\n           ".join(HOSTS)))
        if opts.app_layer:
            fh.write("App routes %s\n"
                     % "\n           ".join("%-32s %s" % (h, opts.app_paths[h]) for h in HOSTS))
        fh.write("Tester     %s on %s\n" % (getpass.getuser(), socket.gethostname()))
        fh.write("Engine     %s: %s\n" % (engine.name, engine.description))
        fh.write("Tool       %s %s\n\n" % (os.path.basename(__file__), VERSION))
        fh.write("Every image shows commands that ran during this capture and their real output.\n")
        fh.write("GCP access was read only (list, describe and get-iam-policy calls). Kubernetes\n")
        fh.write("access was get, describe and auth can-i through a kubeconfig private to this run.\n")
        fh.write("Network tests were nmap TCP connect scans and curl GET, HEAD and OPTIONS requests\n")
        fh.write("to %s and the three published hostnames, each confirmed to resolve into scope\n" % LB_IP)
        fh.write("at the moment it was contacted.\n\n")
        fh.write("Secret values were never requested. Kubernetes secrets are listed by name, type\n")
        fh.write("and key count only, and Cloud SQL accounts by name and host only.\n\n")
        fh.write("In cluster access: %s\n\n" % kube_why)
        if interrupted:
            fh.write("The run was stopped before it finished. Test cases not listed below were not captured.\n\n")
        fh.write("Test cases (%d screenshots)\n" % total)
        fh.write("  result 'false' means the check returned nothing to assess, which the\n")
        fh.write("  client asked to be recorded as a false. 'review' means it returned\n")
        fh.write("  output for the analyst to judge. The permission_denied column of\n")
        fh.write("  _index.csv says whether a refusal is why nothing came back.\n\n")
        for num in sorted(summary):
            t, n = summary[num]
            fh.write("  %2d  %-3d %-8s %s\n" % (num, n, verdicts.get(num, ""), t))
        if denied:
            fh.write("\nTest cases where the granted role was refused a permission. The refusal is in\n")
            fh.write("the image and is a documented limit of the assessment, not a failed command:\n")
            for num, base, t in denied:
                fh.write("  %-12s test case %d, %s\n" % (base, num, t))
        if unexpected:
            fh.write("\nCommands that ended with an unexpected exit code (check the matching image):\n")
            for num, base, cmdtext, state in unexpected:
                fh.write("  %s  %s\n    $ %s\n" % (base, state, cmdtext))
        if skipped_all:
            fh.write("\nNot run:\n")
            for line in skipped_all:
                fh.write("  %s\n" % line)
        fh.write("\nExpected errors that are evidence in their own right:\n")
        fh.write("  A 403 on a describe call means the read only role was not granted that\n")
        fh.write("  permission, so the setting could not be assessed from outside.\n")
        fh.write("  kubectl timing out means the control plane has no reachable public endpoint,\n")
        fh.write("  which is the expected result for a private cluster.\n")
        fh.write("  curl exit 7 or 28 means the port refused or did not answer from the internet.\n")
        fh.write("  An empty nmap result for a port means that port is not reachable publicly.\n")

    zip_path = None
    if not opts.no_zip:
        zip_path = out_dir + ".zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(out_dir):
                for name in sorted(files):
                    full = os.path.join(root, name)
                    zf.write(full, os.path.relpath(full, os.path.dirname(out_dir)))

    print("\n%s: %d screenshots for %d test cases in %s"
          % ("Stopped early" if interrupted else "Done", total, len(summary), out_dir))
    if denied:
        print("%d screenshot(s) show a permission the granted role does not have; "
              "they are listed in _README.txt" % len(denied))
    if unexpected:
        print("%d command(s) ended with an unexpected exit code; they are listed in _README.txt"
              % len(unexpected))
    if zip_path:
        print("Zip: %s" % zip_path)
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
