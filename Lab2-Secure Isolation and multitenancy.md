# Lab 2: Secure Isolation and Multi-Tenancy

**Course:** IKB42603 Cloud Computing Security Essentials  
**Lab:** Lab 2  
**Topic:** Compute, network and storage isolation using Docker and Kubernetes  
**Environment:** kind Kubernetes cluster `ccse-lab2`, Calico CNI, Docker volume `ccse-vol`  
**Name:** Muhamad Syukri Bin Hasbullah

## Lab Summary

This lab demonstrates secure isolation in a multi-tenant cloud environment. Two tenants are represented using separate Kubernetes namespaces, `tenant-a` and `tenant-b`, running on the same shared cluster. The lab first shows that Kubernetes networking is open by default, then applies security controls such as ResourceQuota, NetworkPolicy and RBAC to enforce isolation.

The lab also demonstrates data remanence in container storage by writing sensitive data into a Docker volume, deleting it normally, and comparing that with an overwrite-before-delete method.

## Evidence Folder

All screenshots used for this report are stored in the `Evidence` folder.

| Evidence File | Purpose |
|---|---|
| `0-Create-Cluster.png` | kind cluster `ccse-lab2` creation |
| `0.1-Install-calico.png` | Calico installation and rollout status |
| `1-Create-Tenant.png` | Creation of `tenant-a` and `tenant-b` namespaces |
| `1.2-Deploy-Web.png` | Nginx deployments and services for both tenants |
| `2-TenantB-IP.png` | Tenant B service ClusterIP discovery |
| `2.1-a-tenant-b.png` | Before NetworkPolicy probe showing `tenant-a` can reach `tenant-b` |
| `3-ResourceQuota.png` | ResourceQuota YAML applied to `tenant-a` |
| `3.1-Inspect-RQ.png` | ResourceQuota inspection output |
| `4-deny-ingress.png` | Default-deny ingress NetworkPolicy applied to `tenant-b` |
| `4.1-check-network.png` | Network retest attempt after NetworkPolicy |
| `5-secret.png` | Per-tenant Secret creation |
| `5.1-scoped.png` | ServiceAccount, Role and RoleBinding creation |
| `5.2-Check-Rolebinding.png` | RBAC `can-i` authorization results |
| `6-create-del.png` | Normal delete and remanence scan command |
| `6.1-Secure-wipe.png` | Overwrite-before-delete secure wipe command |

## Setup: Cluster with Policy Enforcement

The lab cluster was created using kind with the default CNI disabled. Calico was then installed so that Kubernetes NetworkPolicy rules are enforced.

Command summary:

```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

Result:

The `ccse-lab2` cluster was created successfully and Calico was installed to enforce network isolation rules.

Evidence:

<img width="656" height="387" alt="Image" src="https://github.com/user-attachments/assets/02e63069-fae5-474c-b0e7-c9644621ea36" />

<img width="651" height="47" alt="Image" src="https://github.com/user-attachments/assets/c706331d-ea9a-4464-891b-fda01fafa1d9" />

<img width="647" height="57" alt="Image" src="https://github.com/user-attachments/assets/4f27d938-a1b3-4714-bfe7-d03a46a42c3a" />


## Task 1: Two Tenants on One Cluster

Two tenants were created as separate Kubernetes namespaces:

```bash
kubectl create namespace tenant-a
kubectl create namespace tenant-b
```

Each tenant was given a simple Nginx web deployment and ClusterIP service:

```bash
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
```

Result:

Both tenants share the same Kubernetes cluster but are separated logically using namespaces. The screenshots show web pods and services created in `tenant-a` and `tenant-b`.

Evidence:

<img width="470" height="73" alt="Image" src="https://github.com/user-attachments/assets/31b638c7-f865-4ee5-8831-6a1bdad98fc2" />

<img width="642" height="75" alt="Image" src="https://github.com/user-attachments/assets/8b4a3447-9709-41aa-b932-7b5872687330" />

<img width="607" height="187" alt="Image" src="https://github.com/user-attachments/assets/c1ad0a5a-0268-484b-bb13-1fad814aa883" />

<img width="648" height="57" alt="Image" src="https://github.com/user-attachments/assets/6c6e9505-b9f6-46f7-a700-c5c1973c1fed" />

## Task 2: Observe the Default-Open Risk

The service IP for Tenant B was retrieved:

```bash
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
```

Observed Tenant B service IP:

```text
10.96.22.249
```

Then a temporary curl pod was launched from `tenant-a` to access the `tenant-b` web service:

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.22.249 -o /dev/null -w 'HTTP %{http_code}\n'
```

Observed output:

```text
HTTP 200
```

Result:

The `HTTP 200` response proves that a pod in `tenant-a` could reach the service in `tenant-b`. This shows the default-open network behavior in Kubernetes. Namespace separation alone does not automatically block network traffic between tenants.

Evidence:


<img width="647" height="90" alt="Image" src="https://github.com/user-attachments/assets/12e35983-ae97-4d40-b6d3-6b0028cf32bd" />



## Task 3: Contain the Noisy Neighbour with ResourceQuota

A ResourceQuota was applied to `tenant-a`:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF
```

Verification command:

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

Observed quota:

```text
pods              Used: 1   Hard: 5
requests.cpu      Used: 0   Hard: 1
requests.memory   Used: 0   Hard: 512Mi
```

Result:

The quota limits `tenant-a` to a maximum of 5 pods, 1 CPU core of total requested CPU and 512 MiB of total requested memory. This prevents one tenant from consuming too much shared cluster capacity.

Evidence:

<img width="476" height="232" alt="Image" src="https://github.com/user-attachments/assets/2d5ecc10-3232-45fc-9e0b-f56fa203ff88" />

<img width="645" height="150" alt="Image" src="https://github.com/user-attachments/assets/f1c7e4eb-d3ad-4be5-a9db-5f6d8d6d1000" />

## Task 4: Default-Deny Network Isolation

A default-deny ingress NetworkPolicy was applied to `tenant-b`:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF
```

Result:

The policy selects all pods in `tenant-b` and denies all incoming traffic because no allowed ingress rules are defined. This implements the default-deny principle: block traffic by default, then allow only what is required.

Evidence:

<img width="632" height="207" alt="Image" src="https://github.com/user-attachments/assets/7808d40a-9f4b-4ed7-808c-1bb5dade01f6" />

### Retest Note

The lab guide expects the same probe from Task 2 to fail or time out after the NetworkPolicy is applied. The current screenshot shows a different failure:

```text
Error from server (Forbidden): pods "probe" is forbidden: failed quota: tenant-a-quota: must specify requests.cpu; requests.memory
```

This means the ResourceQuota is working, but this screenshot does not yet prove the NetworkPolicy blocked traffic. Re-run the probe with resource requests so the temporary pod is allowed to start:

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  --requests='cpu=100m,memory=64Mi' \
  -- curl -s -m 5 http://10.96.22.249 -o /dev/null -w 'HTTP %{http_code}\n'
```

Expected result after the default-deny policy:

```text
HTTP 000
```

or a timeout/error from curl.

Evidence:

<img width="645" height="216" alt="Image" src="https://github.com/user-attachments/assets/82cb255e-943a-4869-8ece-d3f44cca4332" />

## Task 5: Storage and Secret Isolation

Each tenant created its own Kubernetes Secret:

```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

A ServiceAccount, Role and RoleBinding were created for `tenant-a`:

```bash
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

The intended authorization check is:

```bash
SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

Expected result:

```text
yes
no
```

Result:

The ServiceAccount is allowed to read Secrets only in its own namespace, `tenant-a`. It is not allowed to read Secrets from `tenant-b`. This proves storage and secret access isolation using Kubernetes RBAC.

Evidence:

<img width="653" height="117" alt="Image" src="https://github.com/user-attachments/assets/3492c991-f029-4295-bd8b-af33f7069fbc" />

<img width="645" height="146" alt="Image" src="https://github.com/user-attachments/assets/f1ad4f58-5b3f-4471-bcce-04c7fb080cb7" />

<img width="630" height="91" alt="Image" src="https://github.com/user-attachments/assets/a70dc63f-5df4-45db-9b28-cec4d67a83e1" />

### RBAC Note

The screenshot uses `tenant-a:appa` in the RoleBinding and `can-i` check, while the lab guide uses `tenant-a:app-a`. For the cleanest final submission, use `app-a` consistently in both the RoleBinding and the `SA` variable.

## Task 6: Data Remanence and Secure Deletion

The first command creates sensitive data in a Docker volume, deletes the file normally, and searches remaining visible files for the word `SENSITIVE`:

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
   grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

Observed result:

```text
scan-done
```

The second command overwrites the file with zeros before deleting it:

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
   dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt;
echo wiped'
```

Observed result:

```text
1+0 records in
1+0 records out
1024 bytes copied
wiped
```

Result:

The first command demonstrates normal deletion, where `rm` removes the file reference but does not intentionally overwrite the original data. The second command demonstrates overwrite-before-delete by writing zero bytes into the file before removing it. In real cloud storage, cryptographic erasure is preferred because customers usually cannot control the exact physical storage blocks.

Evidence:

<img width="648" height="205" alt="Image" src="https://github.com/user-attachments/assets/24ffe517-e4f5-4970-a560-3ddca42dc127" />

<img width="643" height="132" alt="Image" src="https://github.com/user-attachments/assets/dcfaf6dd-7aba-488f-947a-b9c94ef40ad1" />

## Verification Commands

The lab guide requires these verification commands:

```bash
kubectl get networkpolicy -A
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

Expected verification:

```text
tenant-b   default-deny-ingress
```

and:

```text
Name:            tenant-a-quota
Namespace:       tenant-a
pods             Hard: 5
requests.cpu     Hard: 1
requests.memory  Hard: 512Mi
```

## Short-Answer Questions

### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?

Kubernetes namespaces only organize resources. They don't create network boundaries. By default every pod in a cluster can talk to every pod no matter which namespace it's in because Kubernetes assumes pods should be able to reach each other unless you say otherwise. Nothing blocks the traffic automatically. In a -tenant cloud this is risky because it means one customers pod could potentially scan or connect to another customers pods and services even though they're in "separate" namespaces. If one tenants workload gets hacked the attacker could use that access, to snoop and attack other tenants sharing the same cluster. The fix is to set up NetworkPolicies that block traffic by default and only allow it where its actually needed.

### Q2. Explain the default-deny principle and how your NetworkPolicy implements it.

The default-deny principle means that all traffic gets stopped unless it is clearly permitted. The NetworkPolicy that is set up for `tenant-b` includes all pods by using `podSelector: {}`. It affects `Ingress` traffic. Since the policy does not have any rules all traffic coming into `tenant-b` pods is blocked.

### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

Virtual Machines offer a lot protection than containers. This is because each Virtual Machine has its operating system and kernel. It runs on a hypervisor. The hypervisor is what keeps everything. This makes it really hard for something to breach the boundary between Virtual Machines.Containers are different. They are processes that are isolated from each other. They all share the kernel. This makes them lighter and faster to start. However if there is a problem with the kernel it can affect all the containers. This is because they are all using the kernel.You would use a Virtual Machine boundary when you are not sure if you can trust something. For example if you are running code from customers on the same infrastructure.If you are dealing with sensitive information like credit card numbers or health records. In these cases the risk of something going wrong is too high. It is worth using Virtual Machines even if they use resources because they are more secure. Virtual Machines like gVisor or Kata Containers can also be used. They are like a kind of container that is more secure.

### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

Data remanence means that some data stays on storage devices even after you delete a file. Normally deleting a file just removes the pointer to it and not overwriting the actual bits of information. In the cloud this is really hard to fix. Customers can't control where their data is stored. Data gets copied to disks and data centers to make sure it's safe. Snapshots and backups keep copies. SSDs spread data across cells so overwriting commands might not reach everything. Also many customers share the disks so you can't just destroy a drive without affecting others. The best way to deal with this in the cloud is to use erasure. This works by encrypting data when its not in use. To "delete" the data you just destroy the encryption key. The key is usually kept in a KMS or HSM. Even if encrypted data remains on disks, copies or snapshots it's almost impossible to unlock. This method is fast, easy to check works for each customer separately and meets rules, like GDPRs right to be forgotten. It doesn't need control over the storage.
### Q5. Which of the three isolation dimensions did each task exercise?

| Task | Isolation Dimension | Explanation |
|---|---|---|
| Task 1 | Compute isolation | Tenants were separated into different Kubernetes namespaces while sharing the same cluster. |
| Task 2 | Network isolation risk | The default-open network behavior showed that namespace separation alone does not block traffic. |
| Task 3 | Compute and resource isolation | ResourceQuota limited CPU, memory and pod count to reduce noisy-neighbour risk. |
| Task 4 | Network isolation | NetworkPolicy blocked incoming traffic into `tenant-b` by default. |
| Task 5 | Storage and secret isolation | RBAC restricted secret access so a tenant identity could not read another tenant's secret. |
| Task 6 | Storage isolation and data lifecycle | Normal deletion and overwrite-before-delete demonstrated data remanence and secure deletion concepts. |

## Security Best-Practices Checklist

- [x] Tenants are separated into distinct namespaces.
- [x] Resource quotas prevent a noisy-neighbour from exhausting shared capacity.
- [x] Per-tenant secrets are protected using namespace-scoped RBAC.
- [x] Secure deletion and data remanence are demonstrated using Docker volume commands.
- [ ] Default-deny NetworkPolicy blocks cross-tenant traffic, verified with a corrected post-policy probe.

## Cleanup

After completing the lab and saving all evidence, the environment can be removed:

```bash
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```

## Conclusion

This lab demonstrated that secure multi-tenancy can't rely on any single control,it requires several isolation mechanisms working together. Kubernetes namespaces give you logical separation of resources, but on their own they don't enforce network isolation. ResourceQuota addresses this gap on the compute side by capping shared CPU, memory, and pod usage, while NetworkPolicy handles traffic segmentation to actually restrict which pods can communicate. RBAC adds access control by preventing tenants from reading each other's secrets, and secure deletion practices help mitigate data remanence risk in shared storage. Together, these controls illustrate that true tenant isolation spans compute, network, and storage/access dimensions and not just namespace boundaries alone.
