rule CredentialPKIPKCS8 : Credential PKI PKCS PKCS8 {

    meta:
        name        = "PEM format private key (PKCS#8)"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential PEM format PKCS#8 private key found."

    strings:
        $ascii_pkcs8_0  = /-----BEGIN (ENCRYPTED )?PRIVATE KEY-----(\n|\\n)MII[A-Z0-9=+\/]{20,}/ ascii wide nocase
        $base64_pkcs8_0 = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMII" base64 base64wide
        $base64_pkcs8_1 = "-----BEGIN PRIVATE KEY-----\nMII" base64 base64wide

    condition:
        any of them
}
