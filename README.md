# StorageGRID Large PUT Audit

This standalone PowerShell tool identifies StorageGRID objects associated with the `S3 PUT object size too large` alert.

It reads StorageGRID audit records, finds large `SPUT` events, and separates real oversized single-object uploads from multipart completions. It can optionally verify suspected uploads through the StorageGRID `/grid/object-metadata` API.

## How It Works

The tool:

1. Connects to the StorageGRID Management API and checks the client-writes audit level.
2. Discovers where audit records are stored.
3. Collects large `SPUT` records from the relevant audit files.
4. Uses the `ULID` field to exclude normal multipart completions.
5. Reports non-multipart objects larger than 5 GiB as alert candidates.
6. Optionally checks object metadata and reports whether the internal segment layout resembles a single PUT or multipart upload.

Legal-hold and other metadata-only records are excluded from the candidates and generated reports.

## Portable Bundle

The minimum audit bundle contains these three files:

```text
Invoke-SgLargePutAudit.ps1
Modules/
  SgPutAudit.Api.psm1
  SgPutAudit.Scan.psm1
```

The script imports both modules from the `Modules` directory next to the main script.

Generated reports are written to `./s3-large-put-audit` by default. The directory is created automatically.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- StorageGRID Management API access for `Ssh`, `GenerateScript`, and normal `Ingest` workflows
- SSH access to an Admin Node for `Ssh` mode
- An SSH identity file for non-interactive SSH, or an SSH password entered at the native OpenSSH prompt
- Read access to the audit files when using `LocalFiles` mode

The tool does not require the AWS CLI, PSGallery modules, or administrator privileges on the workstation. All requirements are built-in.

## Modes

### Ssh (Preferred)

SSH mode connects to the grid API, runs the collector over SSH, and immediately processes the results. When
`-SshUser` is omitted, the script prompts for the SSH username and defaults to `admin`. When no
identity file is supplied, the native OpenSSH client prompts for the SSH password. The password is
not passed to PowerShell, included in process arguments, or written to the reports.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-SgLargePutAudit.ps1 `
  -Target https://grid-admin.example.test:8443 `
  -Period 24h `
  -Mode Ssh `
  -VerifyWithObjectMetadata
```

The collector is streamed directly to `bash -s` on the node, so no manual copy or output download
is required. Use `-SshHost` when the SSH hostname is different from the Management API target.
For key-based SSH, add `-SshUser admin -SshIdentityFile $HOME\.ssh\grid-audit-ed25519`.

### GenerateScript

Creates a read-only Bash collector for execution on a StorageGRID Admin Node. This is useful when the `admin` account requires an interactive `su -` session.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-SgLargePutAudit.ps1 `
  -Target https://grid-admin.example.test:8443 `
  -Period 48h `
  -Mode GenerateScript
```

The command prints instructions showing how to copy the generated collector script to the Admin Node, run it, and copy the TSV output back.

### Ingest

Parses collector output that was captured earlier. Use this after running a generated collector on an Admin Node.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-SgLargePutAudit.ps1 `
  -Target https://grid-admin.example.test:8443 `
  -Period 48h `
  -Mode Ingest `
  -CollectorOutputPath .\collector-output.tsv `
  -VerifyWithObjectMetadata
```

`-VerifyWithObjectMetadata` performs lookups only for actual alert-triggering candidates. The current default maximum is 250 lookups; change it with `-MaxMetadataLookups`.

### LocalFiles

Parses audit files that have already been copied to the workstation. This mode does not require a grid API connection unless metadata verification is requested.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Invoke-SgLargePutAudit.ps1 `
  -Mode LocalFiles `
  -LocalAuditPath D:\StorageGRID\audit-export `
  -Period 7d
```

The local scanner supports active and rotated audit files, including date-named files such as `2026-09-22.txt` and compressed files such as `2026-09-21.txt.gz`.

## Periods and Options

Examples of valid periods:

```text
30m     30 minutes
24h     24 hours
3.5d    3.5 days
2w      2 weeks
forever all available records
```

Useful options:

| Option | Purpose |
|---|---|
| `-Target` | StorageGRID Management API hostname or URL |
| `-Credential` | Optional `PSCredential`; otherwise the script prompts |
| `-ValidateCerts` | Validate the Management API certificate |
| `-UseSystemProxy` | Use the configured system proxy |
| `-OutputDir` | Directory for CSV, JSON, and collector files |
| `-IncludeAllNodes` | Scan all applicable audit nodes |
| `-IncludeAllCandidatesInReport` | Include multipart candidates in the report; metadata-only records remain excluded |
| `-VerifyWithObjectMetadata` | Verify alert-triggering records using `/grid/object-metadata` |
| `-MaxMetadataLookups` | Limit metadata API requests |

## Output

Each run creates a timestamped CSV and JSON report, for example:

```text
s3-large-put_20260923T120000.csv
s3-large-put_20260923T120000.json
```

The default report contains real alert-triggering oversized single PUTs. Typical CSV columns include:

```text
AuditTimeUtc
TenantName
Bucket
Key
SizeBytes
SizeGiB
Classification
IsMultipart
MetadataCheck
SegmentCount
SegmentSummary
VersionId
AuditFile
```

Important classifications are:

- `SinglePutOverLimit`: non-multipart object larger than 5 GiB; included as an alert candidate.
- `MultipartComplete`: normal multipart completion; excluded from the default alert report.
- `MultipartOverObjectLimit`: multipart object larger than 5 TiB; included as an alert candidate.
- `ObjectMetadataOperation`: legal-hold or similar metadata-only record; excluded from reports.
- `BelowSinglePutLimit`: not large enough to trigger the alert.

## Fictional Example

Suppose the collector finds these fictional records:

```text
Bucket: research-data
Key: 000012345v001/raw/experiment-01.bin
Size: 6.25 GiB
ULID: absent
Classification: SinglePutOverLimit
```

This is a real alert candidate because it is a non-multipart PUT above 5 GiB.

```text
Bucket: research-data
Key: 000012345v001/raw/experiment-02.bin
Size: 6.25 GiB
ULID: present
Classification: MultipartComplete
```

This is excluded because the object was completed through multipart upload, as ULID is present.

```text
Bucket: research-data
Key: 000012345v001/raw/experiment-03.bin
Size: 8.0 GiB
MetadataCheck: ConfirmedSinglePut
SegmentCount: 9
```

This is a strong confirmation that StorageGRID internally segmented a large single PUT. The metadata check does not replace the audit-log classification; it provides supporting evidence.

A typical summary might look like:

```text
SPUT messages scanned : 12000
Candidate lines        : 640
Outside scan period    : 18
Multipart (excluded)   : 625
Alert triggers         : 15
Verifying suspects against /grid/object-metadata ...
```

The resulting report contains the 15 alert-triggering objects, not the 625 multipart completions or metadata-only records.

## Troubleshooting

### Zero alert candidates

Check the following:

- The client-writes audit level is `normal` or `debug`.
- The requested period includes the object creation time.
- The collector scanned the actual historical file names, not only `audit.log*`.
- The relevant Admin Node or Storage Node audit destination was included.

### Metadata lookup returns HTTP 400

The verifier prefers the bucket/key identifier for version-aware lookups. If a versioned request returns HTTP 400, it retries without the version ID. The report records the final status in `MetadataCheck` and `SegmentSummary`.

### Generated files are too large to review

Use the CSV report for filtering and the JSON report for structured processing. The raw collector TSV is retained as evidence but is not required for future runs after the report has been validated.
