#!/usr/bin/env bash
# Install everything the GCP assessment evidence tool needs on Kali.
set -e
cd "$(dirname "$0")"

echo "== system packages =="
sudo apt update
sudo apt install -y xvfb xterm imagemagick fonts-dejavu-core fonts-nanum \
                    nmap curl openssl dnsutils python3-venv

echo "== python environment =="
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

echo "== google cloud cli =="
if ! command -v gcloud >/dev/null; then
  echo "gcloud was not found. Install the Google Cloud CLI, then re-run this script:"
  echo "  https://cloud.google.com/sdk/docs/install"
  exit 1
fi
gcloud components install kubectl gke-gcloud-auth-plugin --quiet || true

echo
echo "Done. Next:"
echo "  gcloud auth login                 # sign in with the account that has read only access"
echo "  ./.venv/bin/python gcp_assessment_evidence.py --check"
