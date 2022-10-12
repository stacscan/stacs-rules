rule CredentialPKIPKCS8 : Credential PKI PKCS8 {

    meta:
        name        = "PEM format private key (PKCS#8)"
        author      = "Peter Adkins"
        version     = "0.3.0"
        accuracy    = 100
        description = "Potential PEM format PKCS#8 private key found."

    strings:
        $atom_0         = "PRIVATE KEY" ascii wide private
        $atom_1         = "PRIVATE KEY" base64 base64wide private

        $ascii_pkcs8_0  = /-----BEGIN (ENCRYPTED )?PRIVATE KEY-----(\n|\\n)MII[A-Za-z0-9=+\/]{20}/ ascii wide
        $base64_pkcs8_0 = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMII" base64 base64wide
        $base64_pkcs8_1 = "-----BEGIN PRIVATE KEY-----\nMII" base64 base64wide

    condition:
        $atom_0 and (any of ($ascii_*)) or $atom_1 and (any of ($base64_*))
}
