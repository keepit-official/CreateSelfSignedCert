# Create-KeepitSelfSignedCert

A PowerShell script that creates a self-signed RSA certificate and exports it
as three PEM files: the certificate, the private key and the public key. It is
the script linked from the Keepit help centre for customers who need a
certificate and key pair, for example to register an application with a
backup connector.

## Requirements

- Windows. The script relies on `New-SelfSignedCertificate` from the PKI
  module, which only exists on Windows.
- Windows PowerShell 5.1 or PowerShell 7 or later.
- No elevation is needed. The certificate is created in the current user's
  personal store, not the machine store.

## Usage

Download the script, open a PowerShell window in the folder you saved it to,
and run:

```powershell
.\Create-KeepitSelfSignedCert.ps1 -PubKeyFileName public `
    -PrivKeyFileName private -CertFileName certificate.crt
```

The script then prompts for the certificate subject. Only the common name is
required; press Enter to skip any of the optional fields.

```text
Common Name (e.g. server FQDN or your name): backup.example.com
Country Name (2 letter code) (optional): DK
State or Province Name (full name) (optional): Hovedstaden
Locality Name (e.g. city) (optional): Copenhagen
Organization Name (e.g. company) (optional): Example A/S
Organizational Unit Name (e.g. section) (optional): IT
Email Address (optional): it@example.com
Generating self-signed certificate...
Public/private key pair and a self-signed certificate generated successfully.
  Certificate : C:\certs\certificate.crt
  Private key : C:\certs\private.key   (keep this file secret)
  Public key  : C:\certs\public.key
```

Every subject field can also be passed on the command line, which makes the
script fully non-interactive:

```powershell
.\Create-KeepitSelfSignedCert.ps1 -PubKeyFileName public `
    -PrivKeyFileName private -CertFileName certificate.crt `
    -CommonName backup.example.com -CountryName DK `
    -OrganizationName 'Example A/S' -Email it@example.com `
    -OutputDirectory C:\certs
```

If your execution policy blocks the script, run it through
`powershell.exe -ExecutionPolicy Bypass -File <script path>` instead of
changing the policy.

### Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `-PubKeyFileName` | Yes | Public key file name. `.key` is appended unless already present. |
| `-PrivKeyFileName` | Yes | Private key file name. `.key` is appended unless already present. |
| `-CertFileName` | Yes | Certificate file name. Must end in `.cer`, `.pem` or `.crt`. |
| `-CommonName` | Prompted | Subject common name (CN). |
| `-CountryName` | Prompted | Two-letter country code (C). |
| `-ProvinceName` | Prompted | State or province (ST). |
| `-LocalityName` | Prompted | City (L). |
| `-OrganizationName` | Prompted | Organisation (O). |
| `-OrganizationUnitName` | Prompted | Organisational unit (OU). |
| `-Email` | Prompted | Email address (E). |
| `-OutputDirectory` | No | Where to write the files. Defaults to the script's folder. Created if missing. |
| `-KeyLength` | No | RSA key size: 2048 (default), 3072 or 4096. |
| `-ValidityYears` | No | Certificate lifetime in years. Default 2. |
| `-KeepInStore` | No | Leave the certificate in `Cert:\CurrentUser\My` after export. |

Run `Get-Help .\Create-KeepitSelfSignedCert.ps1 -Full` for the same
information straight from the script.

## Output files

| File | Format |
| --- | --- |
| Certificate (`.cer`, `.pem` or `.crt`) | X.509 certificate, PEM, `-----BEGIN CERTIFICATE-----` |
| Private key (`.key`) | Unencrypted PKCS#8, PEM, `-----BEGIN PRIVATE KEY-----` |
| Public key (`.key`) | SubjectPublicKeyInfo, PEM, `-----BEGIN PUBLIC KEY-----` |

All files use 64-character Base64 lines and LF line endings, so they can be
read by OpenSSL and any other standard tooling. The private key is written
without a passphrase. Protect the file accordingly and never send it to anyone,
including Keepit support.

The script refuses to overwrite existing files. Delete or rename the old ones
first if you need to regenerate.

## How it works

1. **Collect the subject.** Each subject field that was not supplied as a
   parameter is prompted for. Values containing X.500 separator characters
   such as commas are quoted. Empty optional fields are left out of the
   subject.
2. **Create the certificate.** `New-SelfSignedCertificate` creates a
   2048-bit RSA key with the Microsoft Software Key Storage Provider and a
   SHA-256 self-signed certificate in `Cert:\CurrentUser\My`. The key is
   marked exportable so that it can be written to a file.
3. **Export the three objects.** The certificate is exported as DER from
   memory. The private key is exported as PKCS#8 via
   `ExportPkcs8PrivateKey` on PowerShell 7, or via the CNG
   `Pkcs8PrivateBlob` export on Windows PowerShell 5.1. The public key is
   exported as SubjectPublicKeyInfo; on Windows PowerShell 5.1, where .NET
   Framework has no direct export, the structure is assembled by hand from
   the certificate's public key bytes.
4. **Write the PEM files** to the output directory.
5. **Clean up.** Unless `-KeepInStore` was given, the certificate and its
   private key are removed from the certificate store again, so nothing is
   left behind on the machine except the files.

Any failure stops the script immediately with a single error message. The
cleanup step still runs.

## Troubleshooting

**`NTE_INVALID_PARAMETER` (0x80090027) from New-SelfSignedCertificate.**
You are running an old copy of the script that still passes
`-KeySpec Signature`. Current Windows builds reject that parameter because the
CNG key storage provider only supports `KeySpec None`. Download the current
version of the script.

**`SEHException` or "An external component has thrown an exception".** The
Windows certificate enrollment layer crashed. Check for a third-party
cryptographic provider, endpoint security hooks or a FIPS policy. Run
`certutil -csptest "Microsoft Software Key Storage Provider"` and look in the
`Microsoft-Windows-CertificateServicesClient-CertEnroll` event log for the
underlying error.

**The script does not run on macOS or Linux.** That is expected, because
`New-SelfSignedCertificate` is Windows-only. On those platforms use
`openssl req -x509 -newkey rsa:2048` instead.

## History

- **2026-10-29** Fixed a string-format error that stopped the script right
  after the common name prompt (reported in SUP-585 on the reworked script).
  The full prompt-to-file flow is now exercised in testing.
- **2026-10-23** Fixed the certificate creation failure reported in SUP-585:
  removed `-KeySpec Signature`, used a real certificate store path and the
  `E=` subject attribute. Fixed the public key file, which previously contained
  the private key. Added error handling, parameters for every input, store
  cleanup and this README.

## Development

Lint with [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer):

```powershell
Invoke-ScriptAnalyzer -Path .\Create-KeepitSelfSignedCert.ps1
```

The script is expected to produce no findings.
