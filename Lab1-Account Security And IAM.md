# Lab 1: Cloud Account Security, Identity and Access Management

**Course:** IKB42603 Cloud Computing Security Essentials  
**Lab:** Lab 1
**Topic:** Identity governance, least privilege, LocalStack IAM and Kubernetes RBAC  
**Environment:** LocalStack on `localhost:4566` and kind Kubernetes cluster `ccse-lab1`
<br> **Name:** Muhamad Syukri

## Lab Summary // Objective

This lab demonstrated account security and access control using two local platforms:

- **LocalStack IAM** was used to simulate AWS IAM users, groups, policies and access keys.
- **Kubernetes RBAC** was used to enforce real authorization decisions using roles and role bindings.

## Evidence Folder

All screenshots used for this report are stored in the `Evidence` folder.

| Evidence File | Purpose |
|---|---|
| `2-Least-privilege.png` | Commands for creating the admin group, attaching policy, creating admin user and verifying membership |
| `2.1-Group-Policy.png` | `Admins` group creation output |
| `2.2-Personal-Admin.png` | `CloudAdmin_Syukri` admin user creation output |
| `2.4-Verify-Membership.png` | `CloudAdmin_Syukri` membership in `Admins` group |
| `3.1-create-user.png` | `Analyst_Syukri` read-only user creation output |
| `3.3-ListPermission-User.png` | `AmazonS3ReadOnlyAccess` attached to `Analyst_Syukri` |
| `4.1-access-key.png` | Access key creation for `Analyst_Syukri` |
| `4.2-List-access-Keys.png` | Access key listing for `Analyst_Syukri` |
| `4-Credential&AccessKeys.png` | Access key rotation command showing deactivation |
| `SessionB-Setup.png` | kind Kubernetes cluster setup |
| `5-Env-Namespace.png` | `dev` and `prod` namespace creation |
| `6-role-bind.png` | Service account, Role and RoleBinding creation |
| `7-test.png` | RBAC authorization test results |
| `Verification-RBAC.png` | RoleBinding YAML verification |

## Task 1: Map the Cloud Identity Landscape

| Concept | AWS Term | Purpose |
|---|---|---|
| All-powerful owner | Root user | The original account owner with full control over all resources and billing. It should be protected and not used for daily administration. |
| Human/app identity | IAM User | A named identity for a person, application or service that needs credentials to access cloud resources. |
| Permission bundle | IAM Policy | A JSON permission document that defines which actions are allowed or denied on specific resources. |
| Collection of users | IAM Group | A way to manage permissions for multiple users together by attaching policies to the group. |
| Temporary identity | IAM Role | An identity that can be assumed temporarily to grant short-lived permissions without long-term user credentials. |

## Session A: LocalStack IAM

### Environment Setup

The AWS CLI was pointed to LocalStack using:

```bash
EP='--endpoint-url=http://localhost:4566'
```

This means AWS CLI commands were sent to the local LocalStack endpoint instead of real AWS.

Verification command:

```bash
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

Output:

```json
{
    "UserId": "000000000000",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

The account ID `000000000000` confirms the commands were executed against LocalStack.

evidence :

<img width="652" height="128" alt="Image" src="https://github.com/user-attachments/assets/fee62359-9552-4eea-8c8f-3a7d11a9d531" />


## Task 2: Create a Least-Privilege Admin

### Step 2.1: Create Admins Group

Command:

```bash
aws $EP iam create-group --group-name Admins
```

Result:

The group `Admins` was created successfully.

Evidence:

<img width="602" height="182" alt="Image" src="https://github.com/user-attachments/assets/86b5e1a7-bf5e-471b-9539-8849ffd637a5" />

### Step 2.2: Attach Administrator Policy to Group

Command:

```bash
aws $EP iam attach-group-policy --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Verification command:

```bash
aws $EP iam list-attached-group-policies --group-name Admins
```

Output:

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

This proves that the `AdministratorAccess` policy was attached to the `Admins` group.

Evidence:

<img width="648" height="40" alt="Image" src="https://github.com/user-attachments/assets/bb7e6af8-dbbe-4eb4-bcc5-910bec2dafcd" />
<img width="647" height="182" alt="Image" src="https://github.com/user-attachments/assets/efa89826-1242-42ae-9d95-24dd46352437" />

### Step 2.3: Create Personal Admin User

Command:

```bash
aws $EP iam create-user --user-name CloudAdmin_Syukri
```

Result:

The user `CloudAdmin_Syukri` was created successfully.

Evidence:

<img width="642" height="187" alt="Image" src="https://github.com/user-attachments/assets/5f3e9cff-2635-47d0-9852-c1f730e0a03a" />

### Step 2.4: Add User to Admins Group and Verify Membership

Command:

```bash
aws $EP iam add-user-to-group --group-name Admins \
    --user-name CloudAdmin_Syukri
```

Verification command:

```bash
aws $EP iam get-group --group-name Admins
```

Output summary:

```json
{
    "Users": [
        {
            "UserName": "CloudAdmin_Syukri",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_Syukri"
        }
    ],
    "Group": {
        "GroupName": "Admins",
        "Arn": "arn:aws:iam::000000000000:group/Admins"
    }
}
```

This proves that `CloudAdmin_Syukri` is a member of the `Admins` group. The admin permission is inherited from the group rather than attached directly to the user.

Evidence:

<img width="647" height="40" alt="Image" src="https://github.com/user-attachments/assets/2d928ee3-6815-488d-8c55-7aeb4495affe" />
<img width="627" height="347" alt="Image" src="https://github.com/user-attachments/assets/7c76c3de-b79e-4911-ac4b-595a7fa38882" />

## Task 3: Enforce Least Privilege with a Scoped Policy

### Step 3.1: Create Read-Only Analyst User

Command:

```bash
aws $EP iam create-user --user-name Analyst_Syukri
```

Result:

The user `Analyst_Syukri` was created successfully.

Evidence:

<img width="598" height="182" alt="Image" src="https://github.com/user-attachments/assets/a09aa0c5-c3c8-4ae5-bc8d-8780139e19ea" />

### Step 3.2: Attach S3 Read-Only Policy

Command:

```bash
aws $EP iam attach-user-policy --user-name Analyst_Syukri \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### Step 3.3: Verify Analyst Permissions

Verification command:

```bash
aws $EP iam list-attached-user-policies --user-name Analyst_Syukri
```

Output:

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        }
    ]
}
```

This proves that `Analyst_Syukri` only has the `AmazonS3ReadOnlyAccess` policy attached.

Evidence:

<img width="647" height="40" alt="Image" src="https://github.com/user-attachments/assets/1d9e86cd-f65d-4d3f-aec3-68bf5b2273a0" />
<img width="648" height="187" alt="Image" src="https://github.com/user-attachments/assets/7ac35b4b-bc3f-4812-b761-36b03059e594" />

### Least Privilege Explanation

- If the `Analyst_Syukri` account were stolen, the damage would be limited because the account only has read-only S3 permissions. 
- The attacker would not have administrator privileges and should not be able to create users, delete resources, change IAM policies or modify data. 
- This reduces the blast radius because the compromised identity can only perform the limited actions granted by its scoped policy.

## Task 4: Credential Hygiene and Access Keys

### Step 4.1: Create Access Key

Command:

```bash
aws $EP iam create-access-key --user-name Analyst_Syukri
```

Result:

An access key was created for `Analyst_Syukri`.

Evidence:

<img width="640" height="188" alt="Image" src="https://github.com/user-attachments/assets/c20f3328-231a-458d-a448-62c11266fd84" />

Security note: the secret access key is not repeated in this report. In real cloud environments, access keys must not be committed to repositories, shared in screenshots or stored in plaintext.

### Step 4.2: List Access Keys

Command:

```bash
aws $EP iam list-access-keys --user-name Analyst_Syukri
```

Output:

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_Syukri",
            "AccessKeyId": "LKIAQAAAAAAANMJV6XA3",
            "Status": "Inactive",
            "CreateDate": "2026-07-29T05:29:06.789002+00:00"
        }
    ]
}
```

Evidence:

<img width="636" height="202" alt="Image" src="https://github.com/user-attachments/assets/6868942c-386f-4629-a465-bb15596e83ce" />
### Step 4.3: Rotate and Deactivate Old Key

Command:

```bash
aws $EP iam update-access-key --user-name Analyst_Syukri \
    --access-key-id LKIAQAAAAAAANMJV6XA3 --status Inactive
```

Result:

The access key status is now `Inactive`, which demonstrates key rotation/deactivation.


## Session B: Kubernetes RBAC

### Setup: Create Local Kubernetes Cluster

Command:

```bash
kind create cluster --name ccse-lab1
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

Result:

The local kind cluster `ccse-lab1` was created and kubectl was configured to use context `kind-ccse-lab1`.

Evidence:

<img width="647" height="273" alt="Image" src="https://github.com/user-attachments/assets/a65e33d0-c6f9-480d-89aa-93a2e9de4f8f" />
<img width="645" height="112" alt="Image" src="https://github.com/user-attachments/assets/9cded89a-290b-4264-8b17-8dc09820f8a6" />
<img width="630" height="60" alt="Image" src="https://github.com/user-attachments/assets/b4f32a09-b3ef-4ff4-b83b-fdcfad10142e" />
## Task 5: Separate Environments with Namespaces

Commands:

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

Result:

The namespaces `dev` and `prod` were created and listed as `Active`.

Evidence:

<img width="643" height="240" alt="Image" src="https://github.com/user-attachments/assets/ea88487b-3654-4756-9f69-b39def785047" />

## Task 6: Define a Role and Bind It

### Step 6.1: Create Service Account

Command:

```bash
kubectl create serviceaccount dev-user -n dev
```

Result:

The service account `dev-user` was created in the `dev` namespace.

### Step 6.2: Create Pod Reader Role

Command:

```bash
kubectl create role pod-reader -n dev \
    --verb=get,list,watch --resource=pods
```

Result:

The Role `pod-reader` was created in the `dev` namespace. It allows only `get`, `list` and `watch` actions on pods.

### Step 6.3: Create RoleBinding

Command:

```bash
kubectl create rolebinding dev-user-binding -n dev \
    --role=pod-reader --serviceaccount=dev:dev-user
```

Result:

The RoleBinding `dev-user-binding` binds the `pod-reader` Role to the `dev-user` service account.

Evidence:

<img width="561" height="40" alt="Image" src="https://github.com/user-attachments/assets/0c4521d3-555a-43e3-816b-f6a74b67dd09" />

<img width="646" height="55" alt="Image" src="https://github.com/user-attachments/assets/5c04a9aa-33be-4b8a-9867-268413a5da39" />

<img width="651" height="56" alt="Image" src="https://github.com/user-attachments/assets/3d73f3a1-962f-404e-ba14-7b882e3af117" />

## Task 7: Test Access Control

The service account identity was stored in a shell variable:

```bash
SA=system:serviceaccount:dev:dev-user
```

This represents the Kubernetes service account `dev-user` in the `dev` namespace.

### Test 1: List Pods in Dev

Command:

```bash
kubectl auth can-i list pods -n dev --as=$SA
```

Result:

```text
yes
```

Explanation:

The service account can list pods in `dev` because the `pod-reader` Role allows `list` on pods in the `dev` namespace.

### Test 2: Delete Pods in Dev

Command:

```bash
kubectl auth can-i delete pods -n dev --as=$SA
```

Result:

```text
no
```

Explanation:

The service account cannot delete pods because the Role only grants `get`, `list` and `watch`. Delete permission was not granted.

### Test 3: List Pods in Prod

Command:

```bash
kubectl auth can-i list pods -n prod --as=$SA
```

Result:

```text
no
```

Explanation:

The service account cannot list pods in `prod` because the Role and RoleBinding are namespaced to `dev`. The permission does not extend to the `prod` namespace.

Evidence:

<img width="598" height="126" alt="Image" src="https://github.com/user-attachments/assets/577d52ac-68eb-46eb-ab05-f40bef139b34" />

### Authentication vs Authorization

The service account identity passes authentication because Kubernetes recognizes the identity `system:serviceaccount:dev:dev-user`. The actions are then checked by authorization. Listing pods in `dev` is allowed because the RoleBinding grants that permission. Deleting pods in `dev` and listing pods in `prod` are blocked by authorization because those permissions were never granted.

## RBAC Verification Command

Required verification command:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

Output:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-07-29T05:48:38Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "701"
  uid: 91124053-fdc5-418a-a916-ec078374971c
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

This confirms that the `dev-user-binding` RoleBinding connects the `dev-user` service account to the `pod-reader` Role in the `dev` namespace.

## Short-Answer Questions

### Q1. Why is attaching policies to groups better than attaching them directly to users?

Attaching policies to groups is generally the better approach because it makes permission management far simpler and more consistent. Instead of assigning the same policy to each user one by one, you attach it once to a group, and every current and future member automatically inherits those permissions. If access needs change, you only update the policy in one place rather than hunting down every individual user who has it. This centralization not only saves time but also reduces the risk of human error.

### Q2. What is the difference between an IAM User and an IAM Role?

An IAM User represents a persistent identity, typically tied to a specific person or application, and it's associated with long-term credentials such as a password for console access or access keys for programmatic use. These credentials remain valid until manually rotated or revoked, which can pose a security risk if not managed carefully.An IAM Role, by contrast, isn't tied to a single person or entity, it's meant to be assumed temporarily by a user, application, or service that needs it. Instead of permanent credentials, a role issues short-lived, temporary security tokens that automatically expire. This makes roles a safer choice for many workloads, since there's no long-lived secret sitting around that could be leaked or misused. Roles also make it easy to grant access only when it's actually needed, rather than having standing permissions active at all times.

### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.

The Analyst_Syukri account illustrates the principle of least privilege because it's granted only the permissions necessary to perform its intended function, in this case, AmazonS3ReadOnlyAccess, allowing it to view S3 resources but not modify or delete them. No broader or administrative access is attached, even though it might be more convenient to grant it.This matters most in a worst-case scenario: if the account's credentials were ever compromised, the attacker would inherit only the permissions the account actually has meaning they could browse S3 data, but couldn't delete resources, alter IAM policies, provision new infrastructure, or create additional privileged accounts. This containment effect is what's meant by "reducing the blast radius" — by limiting what any single identity can do, you limit the maximum possible damage from any single point of failure, rather than letting one compromised account cascade into full environment-wide compromise.

### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?

A Role defines what actions are allowed, such as `get`, `list` and `watch` pods in a namespace. A RoleBinding defines who receives those permissions. In this lab, the `pod-reader` Role defines the pod read permissions, and the `dev-user-binding` RoleBinding grants those permissions to the `dev-user` service account.

### Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?

The developer service account failed to access `prod` because its Role and RoleBinding were created only in the `dev` namespace. Kubernetes RBAC did not grant that identity permission in `prod`. This demonstrates least privilege and separation of environments because access is limited to the exact namespace and actions required.

## Security Best-Practices Checklist

- [x] Root user is not used for daily tasks because a dedicated admin identity, `CloudAdmin_dani`, exists.
- [x] Permissions are granted through the `Admins` group instead of attaching administrator permissions directly to the admin user.
- [x] A least-privilege read-only identity, `Analyst_jiha`, was created and assigned `AmazonS3ReadOnlyAccess`.
- [x] Access keys were created, listed and deactivated to demonstrate rotation.
- [x] Kubernetes RBAC blocked unauthorized actions: deleting pods in `dev` and listing pods in `prod`.

## Conclusion

This lab successfully demonstrated cloud identity management and least privilege. In LocalStack IAM, administrative permissions were assigned through a group, and a separate Analyst user was restricted to read-only S3 access. Access-key hygiene was demonstrated by listing and deactivating the Analyst access key.

In Kubernetes, RBAC enforced a clear access boundary. The `dev-user` service account could list pods in `dev`, but could not delete pods and could not access pods in `prod`. This proves that authorization was applied according to least privilege and namespace separation.
