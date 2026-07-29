# Lab 0: Environment Setup Report

## Course Information

**Course:** IKB42603 Cloud Computing Security Essentials
**Lab:** Lab 0 - Environment Setup
**Name:** Muhamad Syukri Bin Hasbullah
**Date:** 29 July 2026

## Objective

The objective of this setup is to prepare the local lab environment required before Lab 1. Based on the setup cheatsheet, the environment must support Docker, AWS CLI v2, kind, kubectl, OpenSSL, oathtool, LocalStack, and a local Kubernetes cluster.

All services are intended to run locally. LocalStack is used as the local AWS simulator, and kind is used to run Kubernetes inside Docker.

## Environment Summary

Evidence is provided for the Ubuntu environment.

| Component | Kali Verified Version / Status | Ubuntu Proof |
| --- | --- | --- |
| Docker | Docker version 29.6.2, build dfcd4efb | `Evidence/ubuntu/1.docker.png` |
| AWS CLI | aws-cli/2.36.9 Python/3.14.6 Linux/7.0.0-28-generic | `Evidence/ubuntu/2.awscli.png` |
| kind | kind version 0.23.0 | `Evidence/ubuntu/3.kubectl.png` |
| kubectl | Client version v1.36.3, Kustomize v5.8.1 | `Evidence/ubuntu/3.kubectl.png` |
| OpenSSL | OpenSSL 3.5.5 27 Jan 2026 | `Evidence/ubuntu/4.Helper.png` |
| oathtool | OATH Toolkit 2.6.14 | `Evidence/kali/4.Helper.png` |
| LocalStack | Running and healthy on port 4566 (edition: community, version 4.4.0) | `Evidence/ubuntu/5.localstack.png` |
| Kubernetes | kind cluster `ccse` running with node `ccse-control-plane` Ready, version v1.30.0 | `Evidence/ubuntu/5.1.kubenetes.png` |
| AWS CLI LocalStack endpoint | Dummy credentials configured and `sts get-caller-identity` tested through LocalStack | `Evidence/ubuntu/6-config.png` |

## Step 1: Install and Verify Docker

Docker is required to run containers, LocalStack, and the kind Kubernetes cluster.

Docker was installed using the official convenience script:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

Verified with:

```bash
docker --version
```

**Result:**

```
docker --version
Docker version 29.6.2, build dfcd4efb
```

<img width="531" height="185" alt="Docker version" src="https://github.com/user-attachments/assets/d55af859-5647-435f-aaf4-34280a5275d6" />

## Step 2: Install and Verify AWS CLI v2

AWS CLI v2 is required to send AWS-style commands to LocalStack during the labs.

```bash
curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install
```

Verified with:

```bash
aws --version
```

**Result:**

```
aws --version
aws-cli/2.36.9 Python/3.14.6 Linux/7.0.0-28-generic exe/x86_64.ubuntu.26
```

<img width="645" height="186" alt="AWS CLI version" src="https://github.com/user-attachments/assets/52015aad-cd91-4f25-b7e8-7a7e240e61cb" />

No real AWS account is required for this lab because AWS CLI commands are pointed to LocalStack.

## Step 3: Install and Verify kind and kubectl

kind is used to create a local Kubernetes cluster inside Docker. kubectl is used to interact with the Kubernetes cluster.

```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind
sudo snap install kubectl --classic
```

Verified with:

```bash
kind --version
kubectl version --client
```

**Result:**

```
kind --version
kind version 0.23.0

kubectl version --client
Client Version: v1.36.3
Kustomize Version: v5.8.1
```

<img width="385" height="47" alt="kind version" src="https://github.com/user-attachments/assets/732b85e5-7320-47a3-8733-33aba94a6e29" />
<img width="812" height="56" alt="kubectl version" src="https://github.com/user-attachments/assets/9fe1d1a9-e12c-41dc-ba53-86559400eeb1" />

## Step 4: Install and Verify Helper Tools

OpenSSL and oathtool are helper tools used in later labs (encryption/certificates and MFA/TOTP generation).

```bash
sudo apt install oathtool -y
```

Verified with:

```bash
openssl version
oathtool --version
```

**Result:**

```
openssl version
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)

oathtool --version
oathtool (OATH Toolkit) 2.6.14
```

<img width="478" height="92" alt="OpenSSL and oathtool versions" src="https://github.com/user-attachments/assets/45ce06b6-d55c-426d-bc95-56ad6a83d4c9" />

## Step 5: Start and Verify LocalStack

LocalStack provides a local AWS-compatible environment for the labs, pinned to version `4.4.0`:

```bash
docker run -d --name localstack -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack:4.4.0
```

Checked with:

```bash
curl http://localhost:4566/_localstack/health
docker ps
```

**Result:** the health endpoint returned all services as `"available"`, edition `community`, version `4.4.0`. `docker ps` confirmed the `localstack` container is `Up` and `(healthy)`, with port `4566` mapped, alongside the `ccse-control-plane` kind node container.

<img width="530" height="205" alt="LocalStack health and docker ps" src="https://github.com/user-attachments/assets/f965e1aa-a267-4551-a938-e51dca1e65ce" />

## Step 6: Create and Verify the Kubernetes Cluster

The local kind cluster `ccse` was created and verified:

```bash
kind create cluster --name ccse
kubectl cluster-info --context kind-ccse
kubectl get nodes
```

**Result:**

```
kubectl cluster-info --context kind-ccse
Kubernetes control plane is running at https://127.0.0.1:44503
CoreDNS is running at https://127.0.0.1:44503/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

kubectl get nodes
NAME                 STATUS   ROLES           AGE   VERSION
ccse-control-plane   Ready    control-plane   17h   v1.30.0
```

<img width="530" height="312" alt="Kubernetes cluster status" src="https://github.com/user-attachments/assets/190c9007-8c31-4b32-99f8-921da738ddc4" />

## Step 7: Configure AWS CLI for LocalStack

LocalStack accepts dummy credentials, so the AWS CLI was configured with test values:

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
```

The LocalStack endpoint was saved in a variable and tested:

```bash
EP='--endpoint-url=http://localhost:4566'
aws $EP sts get-caller-identity
```

**Result:**

```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

[Letak link gambar AWS CLI / STS caller identity di sini]

This confirms AWS CLI commands are targeting LocalStack instead of real AWS services.

## Pre-Lab Verification Checklist

| Check | Kali OS |
| --- | --- |
| `docker --version` prints a version | Completed |
| `aws --version` prints AWS CLI v2 | Completed |
| `kind --version` works | Completed |
| `kubectl version --client` works | Completed |
| `openssl version` works | Completed |
| `oathtool --version` works | Completed |
| LocalStack health endpoint responds | Completed |
| Kubernetes cluster `ccse` is running | Completed |
| `kubectl get nodes` shows a ready node | Completed |
| AWS CLI dummy credentials are configured | Completed |
| LocalStack endpoint variable is configured | Completed |

## Troubleshooting Notes from the Guide

| Symptom | Recommended Fix |
| --- | --- |
| Cannot connect to Docker daemon | Start Docker Desktop or re-login after adding the Linux user to the `docker` group |
| Docker will not start | Enable hardware virtualization in BIOS/UEFI; on Windows enable WSL 2 and Virtual Machine Platform |
| Port `4566` already in use | Remove the existing LocalStack container with `docker rm -f localstack` and start it again |
| AWS CLI cannot connect to endpoint URL | Start LocalStack and make sure `--endpoint-url=http://localhost:4566` or `$EP` is used |
| `aws`, `kind`, or `kubectl` command not found | Reinstall the tool and open a new terminal so PATH updates are loaded |
| kind cluster creation fails | Make sure Docker is running and has enough memory allocated |
| MFA / TOTP code fails in later labs | Enable automatic system time synchronization |

## Conclusion

The Lab 0 environment setup was completed successfully on Kali. Docker, AWS CLI v2, kind, kubectl, OpenSSL, oathtool, LocalStack, and the local kind Kubernetes cluster were installed and verified. The environment is ready for the next IKB42603 Cloud Computing Security Essentials lab activities using LocalStack and Kubernetes.
