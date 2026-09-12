# Lab 6: Object Storage Security & the Data Security Lifecycle

**Course:** IKB42603 Cloud Computing Security Essentials
**Lab:** Lab 6
**Topic:** Bucket exposure, resource policies, SSE-KMS, versioning and provable deletion — Amazon S3 on LocalStack
**Environment:** Docker container `localstack` (LocalStack Pro, `localstack-pro:latest`, `ENFORCE_IAM=1`), AWS CLI v2, bucket `miit-patient-records-28209`
**Name:** Muhamad Syukri Bin Hasbullah

## Lab Summary

This lab traces the full data security lifecycle on object storage: Session A (Week 11) covers classifying data before storing it, reproducing the archetypal public-bucket breach, remediating it with Block Public Access and least-privilege policy, and comparing identity-based (IAM) vs resource-based (bucket policy) authorisation. Session B (Week 12) covers default encryption at rest (SSE-KMS), delegated access via presigned URLs and the `aws:SecureTransport` condition-key trap, versioning and object-level data remanence, and finally lifecycle rules plus cryptographic erasure for provable deletion.

Several LocalStack Community/Pro emulation limitations surfaced during the lab — Block Public Access not being enforced, an IAM Deny not being enforced despite `ENFORCE_IAM=1`, presigned URL expiry not being enforced, and the `aws:SecureTransport` policy not blocking HTTP calls as expected. Each is documented below with the "verify or explain" reasoning the lab guide calls for, since these gaps between emulated and real AWS behaviour are themselves part of what the lab is testing.

## Evidence Folder

All screenshots used for this report are stored in the `Evidence` folder.

| Evidence File | Purpose |
|---|---|
| `0.1-LocalStack-Pull.png` – `0.4-Caller-Identity.png` | One-time setup: LocalStack Pro pulled, token activated, `sts get-caller-identity` confirms account `000000000000` |
| `1.1-Bucket-Created.png` – `1.4-List-Objects-Tagging.png` | Task 1: bucket created, 3 objects uploaded with classification tags |
| `2.1-Public-Policy-JSON.png` – `2.3-Anonymous-Breach-200.png` | Task 2: public bucket policy applied, anonymous read leaks confidential record |
| `3.1-Block-Public-Access.png` – `3.4-Least-Privilege-Applied.png` | Task 3: Block Public Access enabled (not enforced), least-privilege policy applied |
| `4.1-Create-DataAnalyst-User.png` – `4.6-Both-Requests-Result.png` | Task 4: IAM user, conflicting IAM vs bucket policy, both requests tested |
| `5.1-KMS-Key-Created.png` – `5.4-HeadObject-KMS-Confirmed.png` | Task 5: default SSE-KMS encryption applied and verified |
| `6.1-Presigned-URL-Generated.png` – `6.6-Policy-Removed-Recovery.png` | Task 6: presigned URL, expiry test, SecureTransport policy trap |
| `7.1-Versioning-Enabled.png` – `7.7-Permanent-Version-Deletion.png` | Task 7: versioning, delete marker, data remanence, permanent deletion |
| `8.1-Lifecycle-JSON.png` – `8.6-KMS-Encrypt-Rejected.png` | Task 8: lifecycle rules, KMS key scheduled deletion, cryptographic erasure |
| `9.1-Verification-Command.png` | Final verification command output |

---

## Setup — One-Time Environment Setup

```bash
docker rm -f localstack 2>/dev/null
docker run -d --name localstack -p 4566:4566 \
 -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
 -e ENFORCE_IAM=1 \
 localstack/localstack-pro:latest

export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
aws $EP sts get-caller-identity
```

#### Troubleshooting Note

The `localstack-pro:latest` container initially failed with `License activation failed! No credentials were found in the environment`, because `LOCALSTACK_AUTH_TOKEN` had not yet been exported with a real token value. After registering a free account at app.localstack.cloud and exporting the token (`export LOCALSTACK_AUTH_TOKEN='ls-...'`), the container started successfully and the license activated on the freemium tier.

Result:

LocalStack Pro started with `ENFORCE_IAM=1` (required for Task 4's IAM enforcement), and `sts get-caller-identity` confirmed the dummy account `000000000000`, used throughout the ARNs in this lab.

Evidence:

<img width="940" height="579" alt="Image" src="https://github.com/user-attachments/assets/fde884b8-b5c4-4bff-ad83-db77be5e4e97" />

<img width="940" height="70" alt="Image" src="https://github.com/user-attachments/assets/0962fe2c-6e18-40cf-9f1c-d6c02bd08556" />

<img width="940" height="653" alt="Image" src="https://github.com/user-attachments/assets/0dc925e7-9cc0-40e0-9c74-f4276338fdc4" />

<img width="763" height="234" alt="Image" src="https://github.com/user-attachments/assets/90845088-cc1b-4f78-94df-47a839d17435" />
---

## Session A (Week 11) — Object Storage & the Exposure Problem

### Task 1: Classify the Data Before You Store It

```bash
export BUCKET=miit-patient-records-$RANDOM
aws $EP s3api create-bucket --bucket $BUCKET

echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt

aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
 --body public-notice.txt --tagging 'classification=public'
aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
 --body internal-roster.txt --tagging 'classification=internal'
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
 --body confidential-record.txt --tagging 'classification=confidential'

aws $EP s3api list-objects-v2 --bucket $BUCKET \
 --query 'Contents[].[Key,Size]' --output table
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

Result:

Bucket `miit-patient-records-28209` was created and three objects of different sensitivity were uploaded, each carrying a `classification` tag. `list-objects-v2` confirmed all three objects, and `get-object-tagging` confirmed the `confidential/record.txt` object carries `classification=confidential`. Key names such as `confidential/` are not real folders — S3 has a flat namespace, and the `/` is just part of the object key, which matters because policies grant access by key prefix.

**Data Classification Table**

| Classification | Who may read it | Impact if leaked | Control you will apply |
|---|---|---|---|
| public | Anyone (intended) | Minimal — content is meant to be public | No restriction needed; still hosted in the same bucket for convenience |
| internal | UniKL MIIT staff only | Moderate — internal scheduling info exposed, minor operational risk | Least-privilege bucket policy scoped to `internal/*` (Task 3) |
| confidential | Authorised clinical/admin staff only | Severe — patient-identifiable health data exposed; PDPA/GDPR breach, reputational and legal harm | Block Public Access + SSE-KMS default encryption + no public policy (Tasks 3, 5) |

Evidence:

<img width="790" height="184" alt="Image" src="https://github.com/user-attachments/assets/9b149473-2db0-49e9-b09f-edfb9757cf6f" />

<img width="1045" height="69" alt="Image" src="https://github.com/user-attachments/assets/6d3ab78c-1632-4d33-b17d-c557449980e4" />

<img width="940" height="481" alt="Image" src="https://github.com/user-attachments/assets/3f7c2322-fe54-4526-b0a8-f5edb85f1c99" />

<img width="940" height="355" alt="Image" src="https://github.com/user-attachments/assets/e50323ee-a5bb-4d66-912d-9287c9227abe" />

---

### Task 2: Reproduce the Archetypal Breach

```bash
cat > public-policy.json <<JSON
{
 "Version": "2012-10-17",
 "Statement": [{
 "Sid": "PublicReadEverything",
 "Effect": "Allow",
 "Principal": "*",
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::$BUCKET/*"
 }]
}
JSON
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json

curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
 http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

Observed result:

```text
HTTP 200
Patient: Ahmad bin Ali, Diagnosis: confidential
```

Result:

With no AWS credentials, no CLI, and just a plain HTTP URL, the confidential patient record was read in full. There was no exploit, no malware, and no vulnerability — only a bucket policy that granted `s3:GetObject` to `Principal: "*"`. **The single word `"*"` in the `Principal` field caused the entire exposure.**

Evidence:

<img width="764" height="276" alt="Image" src="https://github.com/user-attachments/assets/07f68fc5-ac4f-4a04-b4b3-0e226e8ac7c1" />

<img width="940" height="247" alt="Image" src="https://github.com/user-attachments/assets/f092f426-d59a-47d2-b3fd-0c4ad9994356" />

<img width="884" height="121" alt="Image" src="https://github.com/user-attachments/assets/00c98fca-1b1b-45ea-a393-29ad322bd440" />

---

### Task 3: Remediate with Block Public Access

```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET

aws $EP s3api put-public-access-block --bucket $BUCKET \
 --public-access-block-configuration \
 BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws $EP s3api get-public-access-block --bucket $BUCKET

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
 http://localhost:4566/$BUCKET/confidential/record.txt
```

Observed result:

```text
PublicAccessBlockConfiguration: all four flags = true
put-bucket-policy: succeeded (not rejected)
anonymous read now: HTTP 200
```

#### Verify / Explain Note

On real AWS, Block Public Access with `BlockPublicPolicy=true` would have **rejected** the `put-bucket-policy` call in step 3, since the policy grants public access. LocalStack accepted the guardrail configuration faithfully (all four flags show `true`) but did not enforce it — the public policy was re-applied successfully and the anonymous read still returned `HTTP 200`.

(a) On real AWS, **`BlockPublicPolicy=true`** is the specific flag that would have rejected the `put-bucket-policy` call, since it blocks any new bucket policy that grants public access.

(b) A **preventative guardrail** (Block Public Access) is stronger than a **detective control** that merely reports the bucket as public, because a detective control only tells you *after* the exposure has already happened — the breach window still exists between the misconfiguration and someone noticing the alert. A preventative guardrail stops the dangerous action (applying a public policy) from ever taking effect in the first place, so a careless engineer's mistake never becomes a live exposure, regardless of how many people have write access to the bucket.

The least-privilege policy scoped to `internal/*` was then applied instead:

```bash
cat > least-privilege-policy.json <<JSON
{
 "Version": "2012-10-17",
 "Statement": [{
 "Sid": "AccountReadInternalOnly",
 "Effect": "Allow",
 "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::$BUCKET/internal/*"
 }]
}
JSON
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilege-policy.json
```

Evidence:

<img width="940" height="261" alt="Image" src="https://github.com/user-attachments/assets/e62fc66d-8689-44ee-8c6a-5bb453c044b6" />

<img width="940" height="76" alt="Image" src="https://github.com/user-attachments/assets/bcd261db-f9fe-46f1-a673-b0c728d9ee3a" />

<img width="696" height="278" alt="Image" src="https://github.com/user-attachments/assets/fd03357c-105e-4b10-9503-c3b4eb347c68" />

<img width="940" height="265" alt="Image" src="https://github.com/user-attachments/assets/20ea3015-a419-4afb-8e8d-403c324cfafa" />


---

### Task 4: Identity Policy vs Resource Policy

```bash
aws $EP iam create-user --user-name DataAnalyst

cat > analyst-iam.json <<'JSON'
{
 "Version": "2012-10-17",
 "Statement": [{
 "Effect": "Allow",
 "Action": ["s3:GetObject", "s3:ListBucket"],
 "Resource": "*"
 }]
}
JSON
aws $EP iam put-user-policy --user-name DataAnalyst \
 --policy-name S3ReadAll --policy-document file://analyst-iam.json

aws $EP iam create-access-key --user-name DataAnalyst \
 --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text

aws configure --profile analyst set aws_access_key_id "$ANALYST_KEY_ID"
aws configure --profile analyst set aws_secret_access_key "$ANALYST_SECRET"
aws configure --profile analyst set region us-east-1

cat > deny-confidential.json <<JSON
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Sid": "AllowAnalystInternal",
 "Effect": "Allow",
 "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::$BUCKET/internal/*"
 },
 {
 "Sid": "DenyAnalystConfidential",
 "Effect": "Deny",
 "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
 "Action": "s3:*",
 "Resource": "arn:aws:s3:::$BUCKET/confidential/*"
 }
 ]
}
JSON
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json

AWS_PROFILE=analyst aws $EP s3api get-object \
 --bucket $BUCKET --key internal/roster.txt analyst-internal.txt && echo "internal: ALLOWED"

AWS_PROFILE=analyst aws $EP s3api get-object \
 --bucket $BUCKET --key confidential/record.txt analyst-conf.txt || echo "confidential: DENIED"
```

Observed result:

```text
internal/roster.txt: succeeded, "internal: ALLOWED" printed
confidential/record.txt: succeeded (full object returned) — expected DENIED, but request was allowed
```

#### Verify / Explain Note

Even with `ENFORCE_IAM=1` set at container start, LocalStack Pro did **not** enforce the explicit `Deny` statement scoped to `confidential/*` — both requests succeeded and returned full object content, rather than the confidential request being blocked. Since LocalStack did not reproduce the deny in practice, the evaluation logic is written out manually below, using both policy documents as evidence.

**Manual evaluation logic** (default deny → any explicit Deny → any explicit Allow):

- **Request 1 — `internal/roster.txt`:** The analyst's IAM identity policy allows `s3:GetObject` on `Resource: "*"`. The bucket policy's `AllowAnalystInternal` statement also explicitly allows `s3:GetObject` on `$BUCKET/internal/*`. No Deny statement matches this resource. Result: **ALLOWED** — decided by the `AllowAnalystInternal` statement (in agreement with the IAM policy).
- **Request 2 — `confidential/record.txt`:** The analyst's IAM identity policy allows `s3:GetObject` on `Resource: "*"` (would normally permit this). However, the bucket policy's `DenyAnalystConfidential` statement explicitly denies `s3:*` on `$BUCKET/confidential/*` for this exact principal. Per AWS evaluation logic, an explicit Deny **always overrides** any Allow, no matter which policy grants it. Result should be **DENIED** — decided by the `DenyAnalystConfidential` statement, which overrides the identity policy's broader Allow.

The Deny policy was removed before Session B as instructed:

```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

Evidence:

<img width="790" height="233" alt="Image" src="https://github.com/user-attachments/assets/d27e4ebe-40f6-4419-98ec-66ef8ba7f5bd" />

<img width="616" height="229" alt="Image" src="https://github.com/user-attachments/assets/62e448a5-fe0b-4f1e-912e-37d9e8deefd9" />

<img width="823" height="51" alt="Image" src="https://github.com/user-attachments/assets/832f6965-24b2-4cea-bd5b-ed0d93be6355" />

<img width="940" height="175" alt="Image" src="https://github.com/user-attachments/assets/d46130a4-5e71-4fa2-9cd4-260ae6f762a6" />

<img width="940" height="432" alt="Image" src="https://github.com/user-attachments/assets/eccbdf98-d80c-45f5-a871-1839a5a17d09" />

<img width="940" height="623" alt="Image" src="https://github.com/user-attachments/assets/2998f54a-116d-47d0-9335-a519aa91f6dc" />

**End of Session A.** `$BUCKET` and all outputs were retained for Session B.

---

## Session B (Week 12) — Protecting, Retaining and Retiring Data

### Task 5: Default Encryption at Rest (SSE-KMS)

```bash
export KEY_ID=$(aws $EP kms create-key \
 --description 'IKB42603 Lab6 patient records bucket key' \
 --query 'KeyMetadata.KeyId' --output text)

cat > encryption.json <<JSON
{
 "Rules": [{
 "ApplyServerSideEncryptionByDefault": {
 "SSEAlgorithm": "aws:kms",
 "KMSMasterKeyID": "$KEY_ID"
 },
 "BucketKeyEnabled": true
 }]
}
JSON
aws $EP s3api put-bucket-encryption --bucket $BUCKET \
 --server-side-encryption-configuration file://encryption.json

aws $EP s3api put-object --bucket $BUCKET \
 --key confidential/record-v2.txt --body confidential-record.txt

aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt \
 --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

Observed result:

```text
aws:kms  arn:aws:kms:us-east-1:000000000000:key/4d966ea8-986b-4759-8c3a-2c62cb56fa3a  True
```

Result:

A dedicated KMS key was created and set as the bucket's default encryption. An object was uploaded with **no** encryption flags at all, and `head-object` confirmed it was still encrypted with `aws:kms` under that key — proof that a default control protected the object without the uploader doing anything. `BucketKeyEnabled: true` applies the envelope-encryption optimisation from Lab 3 at bucket scale: one data key is reused across many objects instead of one KMS call per object, cutting cost and latency without changing confidentiality.

Evidence:

<img width="684" height="115" alt="Image" src="https://github.com/user-attachments/assets/2bdb2078-3426-47b0-bd64-e89c5783eadf" />

<img width="584" height="231" alt="Image" src="https://github.com/user-attachments/assets/a1e31899-5016-4e4f-9324-9732fb3fe0a6" />

<img width="828" height="481" alt="Image" src="https://github.com/user-attachments/assets/9a7845c4-9bf4-47dd-b588-1efb166e88d6" />

<img width="940" height="269" alt="Image" src="https://github.com/user-attachments/assets/fce081a4-2509-476a-b4fd-6202c3d39150" />

---

### Task 6: Delegated Access and the Condition-Key Trap

```bash
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60
URL='<presigned URL>'
curl -s -w ' <-- HTTP %{http_code}\n' "$URL"

sleep 65
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

Observed result:

```text
Immediately: Staff duty schedule, week 12  <-- HTTP 200
After 65s (past the 60s expiry): after expiry: HTTP 200
```

#### Verify / Explain Note

LocalStack did **not** enforce the presigned URL's expiry — the same URL still returned `HTTP 200` after the 60-second window lapsed. Inspecting the URL itself shows the relevant parameters: `X-Amz-Date` binds the moment the URL was signed, `X-Amz-Expires=60` binds how many seconds after that moment the URL should remain valid, and `X-Amz-Signature` is the HMAC-SHA256 signature computed over the request (including those two values) using the signer's secret key — it cryptographically proves the URL was generated by someone holding valid credentials, and that none of its parameters (including the expiry) have been tampered with. On real AWS, the signature verification includes checking the current time against `X-Amz-Date + X-Amz-Expires`; anyone holding a still-valid URL is "fully authorised" because possessing an unexpired, correctly-signed URL **is** the credential — no separate login step is needed.

Now the condition-key trap:

```bash
cat > secure-transport.json <<JSON
{
 "Version": "2012-10-17",
 "Statement": [{
 "Sid": "DenyUnencryptedTransport",
 "Effect": "Deny",
 "Principal": "*",
 "Action": "s3:*",
 "Resource": ["arn:aws:s3:::$BUCKET", "arn:aws:s3:::$BUCKET/*"],
 "Condition": {"Bool": {"aws:SecureTransport": "false"}}
 }]
}
JSON
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json

aws $EP s3api list-objects-v2 --bucket $BUCKET

aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

Observed result:

```text
list-objects-v2: succeeded, full object listing returned (not blocked)
```

#### Verify / Explain Note

The lab guide predicts this policy will lock the user out on LocalStack, since its endpoint is plain `http://` and `aws:SecureTransport` would evaluate to `false` for every request. In this run, however, `list-objects-v2` **succeeded** rather than being denied — another instance of LocalStack not fully enforcing bucket-policy `Condition` blocks in this environment/version. Regardless of which direction the emulation gap goes, the underlying lesson holds: **a condition key must always be evaluated against the environment it will actually run in, not the one it was written for.** A policy copied verbatim from a hardening guide written for HTTPS-only production AWS can behave completely differently against an HTTP-only local emulator — either failing to protect anything (as seen here) or, on real AWS, correctly blocking every plaintext HTTP caller. Testing a security control in the exact target environment, not assuming it behaves the same everywhere, is the only way to know which of those two outcomes you actually get.

Evidence:

<img width="940" height="85" alt="Image" src="https://github.com/user-attachments/assets/d4dc1cfe-d390-4527-b6a8-f9eba066c341" />

<img width="940" height="140" alt="Image" src="https://github.com/user-attachments/assets/35d1014a-8be2-4d2d-9d78-c912c2d159e7" />

<img width="940" height="69" alt="Image" src="https://github.com/user-attachments/assets/65ba0ec6-918b-4dd0-9d93-d196f126d3a2" />

<img width="708" height="296" alt="Image" src="https://github.com/user-attachments/assets/90864728-61a6-4c89-9446-eea30edf6eae" />

<img width="940" height="766" alt="Image" src="https://github.com/user-attachments/assets/8b44406c-72ad-46b7-a197-707144c56bc9" />

<img width="940" height="198" alt="Image" src="https://github.com/user-attachments/assets/d4b7811e-decb-4cc1-8387-69983a7c5f27" />

---

### Task 7: Versioning, Delete Markers & Data Remanence

```bash
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
 --versioning-configuration Status=Enabled

echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt --body rec-v2.txt --query VersionId --output text
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt --body rec-v3.txt --query VersionId --output text

aws $EP s3api list-object-versions --bucket $BUCKET \
 --prefix confidential/record.txt \
 --query 'Versions[].[VersionId,IsLatest,Size]' --output table
```

Observed result:

```text
AaCkiYie012wXv4AIy6lAD7SV93k6fEh | True  | 43   (v3, redacted)
AaCkiYidFaIo856.ko6fwkxsVYANs_SP | False | 48   (v2, hypertension)
null                              | False | 48   (v1, original — from Task 1, before versioning)
```

```bash
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt

aws $EP s3api list-object-versions --bucket $BUCKET \
 --prefix confidential/record.txt \
 --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table

aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt gone.txt

aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
 --version-id null recovered.txt
cat recovered.txt
```

Observed result:

```text
delete-object: DeleteMarker=true, new VersionId created
get-object (no version): NoSuchKey error — "The specified key does not exist"
get-object --version-id null: succeeded
recovered.txt: "Patient: Ahmad bin Ali, Diagnosis: confidential"
```

Result:

"Deleting" the object did not delete any data — it wrote a delete marker over the top, making the object appear gone to an ordinary reader (`NoSuchKey`). But specifying the original version ID (`null`) recovered the **original, unredacted** patient record in full — the exact diagnosis that had been redacted in v3 and then "deleted". This is **object-level data remanence**, and it is why "we deleted the record" is not an acceptable answer to a data-subject erasure request under PDPA or GDPR.

Permanent, per-version deletion was then performed to actually remove the sensitive original:

```bash
aws $EP s3api delete-object --bucket $BUCKET \
 --key confidential/record.txt --version-id null

aws $EP s3api list-object-versions --bucket $BUCKET \
 --prefix confidential/record.txt --query 'Versions[].[VersionId,Size]' --output table
```

Observed result:

```text
AaCkiYie012wXv4AIy6lAD7SV93k6fEh | 43   (v3 remains)
AaCkiYidFaIo856.ko6fwkxsVYANs_SP | 48   (v2 remains)
```

The `null` version (containing the original confidential diagnosis) no longer appears — it was permanently removed.

Evidence:

<img width="829" height="145" alt="Image" src="https://github.com/user-attachments/assets/7cd59b76-0f16-4b30-b1a6-ab33cd7e4d03" />

<img width="940" height="156" alt="Image" src="https://github.com/user-attachments/assets/1dac0cb1-e04b-47af-978f-46961ea53182" />

<img width="881" height="219" alt="Image" src="https://github.com/user-attachments/assets/0063fb85-49a8-443a-9cce-5a1b0d783925" />

<img width="940" height="257" alt="Image" src="https://github.com/user-attachments/assets/ee496d46-981e-464d-a695-c5badb96dcc0" />

<img width="940" height="83" alt="Image" src="https://github.com/user-attachments/assets/f5981fc4-3c20-4001-bf84-a3806e595a84" />

<img width="940" height="349" alt="Image" src="https://github.com/user-attachments/assets/8e105359-d70a-469d-816a-d27555b867d0" />

<img width="890" height="290" alt="Image" src="https://github.com/user-attachments/assets/e6c73d33-7e8e-458a-8da8-84dd1f1be62d" />


---

### Task 8: Lifecycle, Retention & Cryptographic Erasure

```bash
cat > lifecycle.json <<'JSON'
{
 "Rules": [
 {
 "ID": "RetireConfidentialRecords",
 "Filter": {"Prefix": "confidential/"},
 "Status": "Enabled",
 "Expiration": {"Days": 365},
 "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
 },
 {
 "ID": "AbortIncompleteUploads",
 "Filter": {"Prefix": ""},
 "Status": "Enabled",
 "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
 }
 ]
}
JSON
aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
 --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
 --query 'Rules[].[ID,Status]' --output table
```

Observed result:

```text
RetireConfidentialRecords | Enabled
AbortIncompleteUploads    | Enabled
```

```bash
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text
aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.[KeyState,DeletionDate]' --output text

aws $EP s3api get-object --bucket $BUCKET --key confidential/record-v2.txt after-erasure.txt
```

Observed result:

```text
Before: KeyState=Enabled, Enabled=True
After schedule-key-deletion: KeyState=PendingDeletion, DeletionDate=2026-09-17T17:18:02...
get-object after key disabled: succeeded (S3 did not re-check key state on read)
```

#### Verify / Explain Note

As anticipated by the lab guide, LocalStack's S3 read-path did not re-check the KMS key's state — the object was still returned even though its encryption key was `PendingDeletion`. To demonstrate the same principle at the KMS layer directly (per the Lab 3 Task 6 sequence: encrypt → disable-key → decrypt):

```bash
aws $EP kms encrypt --key-id $KEY_ID --plaintext fileb://kms-test.txt \
 --query CiphertextBlob --output text > ciphertext.b64
```

Observed result:

```text
An error occurred (KMSInvalidStateException) when calling the Encrypt operation:
arn:aws:kms:us-east-1:000000000000:key/4d966ea8-986b-4759-8c3a-2c62cb56fa3a is pending deletion.
```

Result:

Unlike the S3 read-path, the **KMS API itself** correctly refused to use the disabled key — even for a fresh `encrypt` operation, not just `decrypt`. This confirms cryptographic erasure works at the layer where it actually matters: once a key is disabled/scheduled for deletion, no ciphertext protected by it can be newly created or (on real AWS) decrypted, regardless of how many copies of the ciphertext exist. Cryptographic erasure gives an auditor **stronger assurance** than overwriting the underlying storage, because in a cloud environment the customer does not control the physical media — snapshots, replicas, and backups may exist entirely outside their visibility or reach. Destroying the key instantly renders every copy of the ciphertext, wherever it physically sits, unreadable noise — a single action achieves what would otherwise require finding and overwriting every physical copy.

Evidence:

<img width="683" height="438" alt="Image" src="https://github.com/user-attachments/assets/e2c6db33-4508-48be-8ed8-9e1c79901795" />

<img width="940" height="120" alt="Image" src="https://github.com/user-attachments/assets/dce675df-76be-40b8-8816-1d7feda53754" />

<img width="939" height="181" alt="Image" src="https://github.com/user-attachments/assets/d7e732ee-38e0-424d-a84b-6cce0136f79d" />

<img width="940" height="284" alt="Image" src="https://github.com/user-attachments/assets/3c42d622-3221-4ac6-b890-b3540e1247b8" />

<img width="940" height="308" alt="Image" src="https://github.com/user-attachments/assets/98c9b646-7422-40c9-89c3-cfebe41e53c9" />

<img width="940" height="122" alt="Image" src="https://github.com/user-attachments/assets/444a5ea7-3e13-45cf-8917-8dc37d3fa750" />

---

## Verification Command

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="
aws $EP s3api get-public-access-block --bucket $BUCKET \
 --query 'PublicAccessBlockConfiguration' --output text
aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text
aws $EP s3api get-bucket-encryption --bucket $BUCKET \
 --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
 --output text
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
 --query 'Rules[].[ID,Status]' --output text
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text
```

Observed result:

```text
=== IKB42603 Lab 6 verification: miit-patient-records-28209 ===
True    True    True    True
Enabled
aws:kms    4d966ea8-986b-4759-8c3a-2c62cb56fa3a
RetireConfidentialRecords    Enabled
AbortIncompleteUploads       Enabled
PendingDeletion
```

Result:

The bucket's final security posture: Block Public Access fully enabled (all 4 flags), versioning enabled, default encryption is `aws:kms` under a customer-managed key, both lifecycle rules enabled, and the KMS key is in `PendingDeletion` state following the cryptographic erasure in Task 8.

Evidence:

<img width="940" height="341" alt="Image" src="https://github.com/user-attachments/assets/79610750-dadf-415a-bc0b-8464b43811e5" />
---

## Short-Answer Questions

### Q1. Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?

The single word **`"*"`** in the `"Principal"` field caused the exposure — it grants the permission to literally anyone on the internet, with no identity check at all.

`Principal: "*"` on a **bucket policy** is more dangerous than an over-broad IAM policy on one user because of *scope of reach*. An over-broad IAM policy, however dangerous, still only grants that access to a single, identifiable, credentialed principal — someone still needs that specific user's credentials to exploit it, and the blast radius is bounded to whatever that one identity can do. `Principal: "*"` on a resource policy removes the identity requirement entirely: it does not matter who is asking or whether they have any AWS credentials whatsoever, as demonstrated in Task 2 where a plain `curl` with no credentials read the confidential record. The attack surface goes from "anyone who steals this one user's keys" to "literally anyone with the URL," which is an unbounded population.

### Q2. Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?

An **identity-based policy** is attached to a *principal* (a user, group, or role) and defines what that principal is allowed to do, generally across resources. The `S3ReadAll` policy attached to `DataAnalyst` in Task 4 is identity-based — it says "this user may `GetObject`/`ListBucket` on any resource."

A **resource-based policy** is attached to the *resource itself* (here, the bucket) and defines who may act on it. The `deny-confidential.json` bucket policy in Task 4 is resource-based — it names specific principals and grants or denies them access to specific parts of this one bucket.

By AWS evaluation logic (default deny → explicit Deny → explicit Allow), the **`internal/roster.txt`** request was decided in agreement by both policies (the identity policy's broad Allow and the bucket policy's `AllowAnalystInternal` statement), so it should be **ALLOWED**. The **`confidential/record.txt`** request should have been decided by the bucket policy's `DenyAnalystConfidential` statement, whose explicit Deny overrides the identity policy's broader Allow — it should be **DENIED**, regardless of what the identity policy permits. (As documented above, LocalStack did not actually enforce this Deny in this environment, so this is the evaluation logic worked out manually rather than the observed live result.)

### Q3. Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?

A **control** (like a bucket policy) is something an individual engineer configures per-resource, at their discretion, for a specific purpose — it can be correctly applied, forgotten, misconfigured, or deliberately loosened by any one person with access. A **guardrail** (like Block Public Access) sits above individual controls, at the account or bucket level, and *overrides* whatever any individual control tries to do — it cannot be bypassed just by one engineer writing a permissive policy.

This distinction matters most in an organisation with many engineers because controls rely on every single person, every single time, getting the configuration right — one mistake by one engineer is enough to cause a breach. A guardrail removes that single point of failure: even if a careless or rushed colleague reintroduces a public policy (exactly as simulated in Task 3), the guardrail is designed to refuse it before it takes effect. It converts security from "hope everyone always does it right" into "the platform itself won't allow the dangerous state," which scales far better than relying on individual diligence across a large team.

### Q4. Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.

No — SSE-KMS does **not** protect the confidential record from the analyst in Task 4. Server-side encryption at rest protects data from threats to the **underlying storage media** — for example, someone who steals a physical disk, gains unauthorised access to the storage backend directly, or accesses old/leftover data blocks outside the normal S3 API. It does not protect data from someone who is authorised, via IAM or a bucket policy, to make a normal `GetObject` API call: S3 transparently decrypts the object for any request that is authorised to read it, so from the analyst's perspective (assuming the Deny were not in place) the object would be returned in plaintext exactly as if it were unencrypted. Encryption at rest is a defence against storage-level compromise, not a substitute for access control — that is precisely why Task 4's explicit Deny statement is the control that actually decides whether the analyst can read the confidential prefix, not the encryption configuration from Task 5.

### Q5. A patient invokes their right to erasure. Using your Task 7 evidence, explain why delete-object alone is not compliant, and describe two mechanisms that would make the deletion provable.

Task 7 showed that a plain `delete-object` call on a versioned bucket does not delete any data — it only writes a **delete marker** on top of the existing versions. The object appears gone to an ordinary `get-object` call (`NoSuchKey`), but the original, unredacted patient record was still fully readable with `get-object --version-id null`. If a patient exercises their PDPA/GDPR right to erasure and the organisation responds with an ordinary `delete-object`, the patient's actual sensitive data is still sitting in the bucket, retrievable by anyone with the right version ID or `s3:GetObjectVersion` permission — that does not satisfy an erasure obligation.

Two mechanisms that make deletion **provable**:

1. **Permanent, per-version deletion** — explicitly calling `delete-object` with the specific `--version-id` of every version containing the patient's data (as done at the end of Task 7), and then listing versions again to show none remain. This is auditable: a before/after `list-object-versions` comparison can be produced as evidence that the specific version IDs no longer exist.
2. **Cryptographic erasure** — disabling and scheduling deletion of the KMS key that encrypted the object (Task 8). Even if a copy of the ciphertext survives somewhere (a backup, a replica, a snapshot the organisation does not fully control), it becomes permanently unreadable once the key is gone, which is provable via `kms describe-key` showing `KeyState: PendingDeletion`/eventually `Unavailable`, and by demonstrating (as in Task 8) that further `kms encrypt`/`decrypt` calls against that key fail with `KMSInvalidStateException`.

### Q6. You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.

| Command | Control it evidences |
|---|---|
| `aws s3api get-public-access-block --bucket $BUCKET` | Evidences that Block Public Access is configured with all four flags `true` — the organisation's public-exposure guardrail is in place. |
| `aws s3api get-bucket-encryption --bucket $BUCKET` | Evidences that default server-side encryption (`aws:kms`, with the specific customer-managed key ID) is enforced on the bucket, satisfying an encryption-at-rest requirement. |
| `aws kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState'` | Evidences the lifecycle state of the encryption key — e.g. proving a key was genuinely scheduled for deletion (`PendingDeletion`) as part of a provable data-erasure event, tying the KMS action to the data-subject request it fulfilled. |

(A fourth reasonable choice would be `aws s3api get-bucket-versioning` to evidence that versioning — and therefore an audit trail of every object revision — is enabled, or `aws s3api get-bucket-lifecycle-configuration` to evidence that a documented, automated retention policy exists rather than relying on manual deletion.)

---

## Security Best-Practices Checklist

- [x] Every object carries a classification tag before any access decision is made.
- [x] No bucket policy names `Principal: "*"` in the final state; anonymous access was tested and found to leak data before remediation.
- [x] Block Public Access is enabled on all four flags (LocalStack does not fully enforce it, but configuration was verified as set correctly).
- [x] Access is granted by least privilege and scoped to a key prefix (`internal/*`), never to `/*` by default in the final policy.
- [x] Default encryption at rest is `aws:kms` with a customer-managed key.
- [x] Sharing uses time-bounded presigned URLs, not permanent public objects (expiry enforcement is a LocalStack limitation, documented above).
- [x] Versioning is enabled, and delete markers were shown not to destroy data.
- [x] A lifecycle configuration expresses the retention policy, and cryptographic erasure was demonstrated for provable deletion.

---

## Cleanup

```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET

aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
 list-object-versions --bucket $BUCKET --output json \
 --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
 list-object-versions --bucket $BUCKET --output json \
 --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"

aws $EP s3api list-object-versions --bucket $BUCKET --output text
aws $EP s3api delete-bucket --bucket $BUCKET

aws $EP iam list-access-keys --user-name DataAnalyst
aws $EP iam delete-access-key --user-name DataAnalyst --access-key-id $ANALYST_KEY_ID
aws $EP iam delete-user-policy --user-name DataAnalyst --policy-name S3ReadAll
aws $EP iam delete-user --user-name DataAnalyst

docker rm -f localstack
rm -f *.json *.txt
```

#### Troubleshooting Note

A versioned bucket cannot be emptied with `s3 rb --force`, since that command ignores non-current versions and delete markers — every version had to be explicitly deleted first, exactly as Task 7 demonstrated at object scale. Separately, `iam delete-user` initially failed with `DeleteConflict: Cannot delete entity, must delete access keys first`, since the `DataAnalyst` user still had an active access key from Task 4. The access key had to be deleted (via `iam delete-access-key`) before the user itself could be removed.

Result:

The bucket was fully emptied of all object versions and delete markers before deletion, and the `DataAnalyst` IAM user, policy, and access key were removed. The LocalStack container was then stopped and removed, returning the environment to a clean state.

---

## Conclusion

This lab traced the complete data security lifecycle for object storage, from classification through to provable destruction. Session A showed that the single most common real-world cloud breach — a public bucket — reduces to one dangerous word in a policy (`Principal: "*"`), and that fixing it requires both removing the bad policy and installing a guardrail (Block Public Access) that survives future mistakes; it also showed that identity policies and resource policies are evaluated together, with an explicit Deny always meant to win. Session B showed that default encryption protects data at rest but not from authorised-but-wrong access, that delegated access via presigned URLs trades convenience for the risk that anyone holding the URL is fully authorised, that a security condition written for one environment (HTTPS) can behave unpredictably in another (HTTP), and — most strikingly — that "delete" on a versioned object does not actually erase data, which is why compliant erasure requires either explicit per-version deletion or cryptographic erasure of the encryption key. Several LocalStack emulation gaps (Block Public Access, IAM Deny, presigned URL expiry, and the SecureTransport condition all failing to enforce as they would on real AWS) turned out to be as instructive as the working parts of the lab, reinforcing that security controls must always be verified in the exact environment they will run in, not assumed correct from documentation or from how they behave elsewhere.
