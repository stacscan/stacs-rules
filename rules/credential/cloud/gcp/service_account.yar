rule CredentialCloudGCPServiceAccount : Credential Cloud GCP {

    meta:
        name        = "GCP Service Account JSON"
        author      = "Peter Adkins"
        version     = "0.4.0"
        accuracy    = 100
        description = "Potential GCP service account JSON found."

    strings:
        $atom_0   = "client_x509_cert_url" wide ascii private
        $atom_1   = "client_x509_cert_url" base64 base64wide private

        $ascii_0  = "\"client_x509_cert_url\"" wide ascii private
        $ascii_1  = "\"private_key\"" wide ascii private
        $ascii_2  = "\"client_email\"" wide ascii

        $base64_0 = "\"client_x509_cert_url\"" base64 base64wide private
        $base64_1  = "\"private_key\"" base64 base64wide private
        $base64_2  = "\"client_email\"" base64 base64wide

    condition:
        any of ($atom_*) and (
            all of ($ascii_*)
        ) or (
            all of ($base64_*)
        )
}
