#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a self-signed RSA certificate and exports it as PEM files.

.DESCRIPTION
    Generates a 2048-bit (by default) RSA key pair and a self-signed X.509
    certificate using the Windows certificate enrollment API, then writes three
    PEM-encoded files to the output directory:

      * the certificate  (-----BEGIN CERTIFICATE-----)
      * the private key  (-----BEGIN PRIVATE KEY-----, PKCS#8)
      * the public key   (-----BEGIN PUBLIC KEY-----, SubjectPublicKeyInfo)

    The certificate is created in the Cert:\CurrentUser\My store because that is
    the only kind of location New-SelfSignedCertificate accepts. Once the files
    have been written the certificate and its key are removed from the store
    again unless -KeepInStore is specified.

    Any subject field that is not supplied on the command line is prompted for.
    Only the common name is required; empty optional fields are left out of the
    subject.

    This script requires Windows PowerShell 5.1 or PowerShell 7 on Windows,
    because New-SelfSignedCertificate (PKI module) is Windows-only.

.PARAMETER PubKeyFileName
    File name for the public key. ".key" is appended unless already present.

.PARAMETER PrivKeyFileName
    File name for the private key. ".key" is appended unless already present.

.PARAMETER CertFileName
    File name for the certificate. Must end in .cer, .pem or .crt.

.PARAMETER CommonName
    Subject common name (CN), for example a server FQDN or your name.

.PARAMETER CountryName
    Two-letter ISO country code (C).

.PARAMETER ProvinceName
    State or province (ST).

.PARAMETER LocalityName
    City or locality (L).

.PARAMETER OrganizationName
    Organisation (O).

.PARAMETER OrganizationUnitName
    Organisational unit (OU).

.PARAMETER Email
    Email address (E).

.PARAMETER OutputDirectory
    Directory the three files are written to. Defaults to the directory the
    script is in. It is created if it does not exist.

.PARAMETER KeyLength
    RSA key size in bits. 2048 (default), 3072 or 4096.

.PARAMETER ValidityYears
    Number of years the certificate is valid for. Defaults to 2.

.PARAMETER KeepInStore
    Leave the certificate and private key in Cert:\CurrentUser\My after the
    files have been written. By default they are removed.

.EXAMPLE
    PS> .\Create-KeepitSelfSignedCert.ps1 -PubKeyFileName public -PrivKeyFileName private -CertFileName certificate.crt

    Prompts for the subject fields, then writes public.key, private.key and
    certificate.crt next to the script.

.EXAMPLE
    PS> .\Create-KeepitSelfSignedCert.ps1 -PubKeyFileName public -PrivKeyFileName private -CertFileName certificate.crt -CommonName backup.example.com -CountryName DK -OrganizationName 'Example A/S' -Email it@example.com -OutputDirectory C:\certs

    Runs without any interactive prompts.

.NOTES
    Change history
    2026-10-29  Fixed a string-format error on the first subject field that
                stopped the script right after the common name prompt.
    2026-10-23  Removed -KeySpec Signature (rejected by the CNG provider on
                current Windows builds), use a real certificate store path and
                the E= subject attribute (SUP-585). Fixed the public key file,
                which previously contained the private key. Added error
                handling, parameters for all inputs and store cleanup.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PubKeyFileName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PrivKeyFileName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('(?i)\.(cer|pem|crt)$')]
    [string]$CertFileName,

    [string]$CommonName,
    [ValidatePattern('^([A-Za-z]{2})?$')]
    [string]$CountryName,
    [string]$ProvinceName,
    [string]$LocalityName,
    [string]$OrganizationName,
    [string]$OrganizationUnitName,
    [string]$Email,

    [string]$OutputDirectory = $PSScriptRoot,

    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength = 2048,

    [ValidateRange(1, 50)]
    [int]$ValidityYears = 2,

    [switch]$KeepInStore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helper functions

function ConvertTo-PemBlock {
    <#
    .SYNOPSIS
        Wraps DER bytes in a PEM envelope with 64-character Base64 lines (RFC 7468).
    #>
    param (
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $base64 = [Convert]::ToBase64String($Bytes)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("-----BEGIN $Label-----")
    for ($i = 0; $i -lt $base64.Length; $i += 64) {
        $lines.Add($base64.Substring($i, [Math]::Min(64, $base64.Length - $i)))
    }
    $lines.Add("-----END $Label-----")
    return ($lines -join "`n") + "`n"
}

function ConvertTo-DerElement {
    <#
    .SYNOPSIS
        Prefixes content bytes with a DER tag and length.
    #>
    param (
        [Parameter(Mandatory = $true)][byte]$Tag,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Content
    )
    $length = $Content.Length
    if ($length -lt 0x80) {
        $header = [byte[]]@($Tag, $length)
    }
    else {
        # Long form: 0x80 | number of length bytes, then the length big-endian
        # without leading zero bytes.
        $lengthBytes = New-Object System.Collections.Generic.List[byte]
        $remaining = $length
        while ($remaining -gt 0) {
            $lengthBytes.Insert(0, [byte]($remaining -band 0xFF))
            $remaining = $remaining -shr 8
        }
        $header = [byte[]](@($Tag, [byte](0x80 -bor $lengthBytes.Count)) + $lengthBytes.ToArray())
    }
    return [byte[]]($header + $Content)
}

function Get-SubjectPublicKeyInfo {
    <#
    .SYNOPSIS
        Returns the DER-encoded SubjectPublicKeyInfo for a certificate's public key.
    .DESCRIPTION
        PowerShell 7 (.NET Core) can export this directly. Windows PowerShell 5.1
        (.NET Framework) cannot, so the structure is assembled from the pieces the
        X509Certificate2.PublicKey property exposes:
            SEQUENCE {
                SEQUENCE { OID algorithm, parameters }
                BIT STRING { 0x00, PKCS#1 RSAPublicKey }
            }
    #>
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if ($rsa.PSObject.Methods.Name -contains 'ExportSubjectPublicKeyInfo') {
        return $rsa.ExportSubjectPublicKeyInfo()
    }

    if ($Certificate.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1') {
        throw "Unexpected public key algorithm OID $($Certificate.PublicKey.Oid.Value); expected rsaEncryption."
    }
    # AlgorithmIdentifier for rsaEncryption: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
    $algorithmIdentifier = [byte[]]@(0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)
    $bitString = ConvertTo-DerElement -Tag 0x03 -Content ([byte[]](@(0x00) + $Certificate.PublicKey.EncodedKeyValue.RawData))
    return ConvertTo-DerElement -Tag 0x30 -Content ([byte[]]($algorithmIdentifier + $bitString))
}

function Get-Pkcs8PrivateKey {
    <#
    .SYNOPSIS
        Returns the DER-encoded, unencrypted PKCS#8 private key for a certificate.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) {
        throw 'The certificate has no accessible RSA private key.'
    }
    if ($rsa.PSObject.Methods.Name -contains 'ExportPkcs8PrivateKey') {
        return $rsa.ExportPkcs8PrivateKey()
    }
    # Windows PowerShell 5.1: the key is an RSACng; export the CNG PKCS#8 blob.
    return $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
}

function Add-KeyExtension {
    param ([Parameter(Mandatory = $true)][string]$FileName)
    if ($FileName -match '\.key$') { return $FileName }
    return "$FileName.key"
}

function Format-SubjectValue {
    <#
    .SYNOPSIS
        Quotes a relative distinguished name value if it contains X.500 separators.
    #>
    param ([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -match '[,+="<>#;\\]') {
        return '"' + ($Value -replace '"', '""') + '"'
    }
    return $Value
}

#endregion

#region Platform check

$isWindowsHost = ($PSVersionTable.PSEdition -eq 'Desktop') -or
    (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
if (-not $isWindowsHost) {
    throw 'This script uses New-SelfSignedCertificate, which is only available on Windows.'
}
if (-not (Get-Command -Name New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    throw 'New-SelfSignedCertificate was not found. Make sure the PKI module is installed.'
}

#endregion

#region Collect subject fields

$subjectFields = [ordered]@{
    CommonName           = @{ Attribute = 'CN'; Prompt = 'Common Name (e.g. server FQDN or your name)' }
    CountryName          = @{ Attribute = 'C';  Prompt = 'Country Name (2 letter code)' }
    ProvinceName         = @{ Attribute = 'ST'; Prompt = 'State or Province Name (full name)' }
    LocalityName         = @{ Attribute = 'L';  Prompt = 'Locality Name (e.g. city)' }
    OrganizationName     = @{ Attribute = 'O';  Prompt = 'Organization Name (e.g. company)' }
    OrganizationUnitName = @{ Attribute = 'OU'; Prompt = 'Organizational Unit Name (e.g. section)' }
    Email                = @{ Attribute = 'E';  Prompt = 'Email Address' }
}

$subjectParts = New-Object System.Collections.Generic.List[string]
foreach ($name in $subjectFields.Keys) {
    $value = Get-Variable -Name $name -ValueOnly
    if (-not $PSBoundParameters.ContainsKey($name)) {
        $suffix = if ($name -eq 'CommonName') { '' } else { ' (optional)' }
        $value = Read-Host -Prompt ($subjectFields[$name].Prompt + $suffix)
    }
    $value = $value.Trim()
    if ($name -eq 'CommonName' -and [string]::IsNullOrEmpty($value)) {
        throw 'A common name is required.'
    }
    if ($name -eq 'CountryName' -and $value -notmatch '^([A-Za-z]{2})?$') {
        throw 'The country name must be a two-letter code.'
    }
    if (-not [string]::IsNullOrEmpty($value)) {
        $subjectParts.Add(('{0}={1}' -f $subjectFields[$name].Attribute, (Format-SubjectValue -Value $value)))
    }
}
$subject = $subjectParts -join ','

#endregion

#region Resolve output paths

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = (Get-Location).Path
}
if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory
}
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

$certPath = Join-Path -Path $OutputDirectory -ChildPath $CertFileName
$privateKeyPath = Join-Path -Path $OutputDirectory -ChildPath (Add-KeyExtension -FileName $PrivKeyFileName)
$publicKeyPath = Join-Path -Path $OutputDirectory -ChildPath (Add-KeyExtension -FileName $PubKeyFileName)

foreach ($path in @($certPath, $privateKeyPath, $publicKeyPath)) {
    if (Test-Path -LiteralPath $path) {
        throw "Refusing to overwrite existing file: $path"
    }
}

#endregion

#region Create certificate and write files

$storeLocation = 'Cert:\CurrentUser\My'
$cert = $null

Write-Verbose "Subject: $subject"
Write-Information -MessageData 'Generating self-signed certificate...' -InformationAction Continue

try {
    $cert = New-SelfSignedCertificate `
        -Subject $subject `
        -CertStoreLocation $storeLocation `
        -NotAfter (Get-Date).AddYears($ValidityYears) `
        -KeyExportPolicy Exportable `
        -KeyAlgorithm RSA `
        -KeyLength $KeyLength `
        -HashAlgorithm SHA256

    $certificateDer = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $privateKeyDer = Get-Pkcs8PrivateKey -Certificate $cert
    $publicKeyDer = Get-SubjectPublicKeyInfo -Certificate $cert

    $ascii = [System.Text.Encoding]::ASCII
    [System.IO.File]::WriteAllText($certPath, (ConvertTo-PemBlock -Bytes $certificateDer -Label 'CERTIFICATE'), $ascii)
    [System.IO.File]::WriteAllText($privateKeyPath, (ConvertTo-PemBlock -Bytes $privateKeyDer -Label 'PRIVATE KEY'), $ascii)
    [System.IO.File]::WriteAllText($publicKeyPath, (ConvertTo-PemBlock -Bytes $publicKeyDer -Label 'PUBLIC KEY'), $ascii)
}
finally {
    if ($cert -and -not $KeepInStore) {
        $storePath = "$storeLocation\$($cert.Thumbprint)"
        try {
            Remove-Item -LiteralPath $storePath -DeleteKey -ErrorAction Stop
            Write-Verbose "Removed certificate $($cert.Thumbprint) from $storeLocation."
        }
        catch {
            Write-Warning "Could not remove certificate $($cert.Thumbprint) from ${storeLocation}: $($_.Exception.Message)"
        }
    }
}

$summary = @(
    'Public/private key pair and a self-signed certificate generated successfully.'
    "  Certificate : $certPath"
    "  Private key : $privateKeyPath   (keep this file secret)"
    "  Public key  : $publicKeyPath"
)
if ($KeepInStore) {
    $summary += "  Store entry : $storeLocation\$($cert.Thumbprint)"
}
Write-Information -MessageData ($summary -join [Environment]::NewLine) -InformationAction Continue

#endregion
