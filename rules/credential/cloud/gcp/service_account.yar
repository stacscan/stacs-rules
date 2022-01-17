rule CredentialCloudGCPServiceAccount : Credential Cloud GCP {

    meta:
        name        = "GCP Service Account JSON"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential GCP service account JSON found."

    strings:
        $ascii_0  = "\"client_x509_cert_url\"" nocase wide ascii private
        $ascii_1  = "\"private_key\"" nocase wide ascii private
        $ascii_2  = "\"client_email\"" nocase wide ascii

        $base64_0 = "\"client_x509_cert_url\"" base64 base64wide private
        $base64_1  = "\"private_key\"" base64 base64wide private
        $base64_2  = "\"client_email\"" base64 base64wide

    condition:
        ($ascii_0 and $ascii_1 and $ascii_2)
        or
        ($base64_0 and $base64_1 and $base64_2)
}
