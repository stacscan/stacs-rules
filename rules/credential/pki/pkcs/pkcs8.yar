rule CredentialPKIPKCS8 : Credential PKI PKCS {

    meta:
        name        = "PEM format private key (PKCS#8)"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential PEM format PKCS#8 private key found."

    strings:
        $pkcs8_0 = /-----BEGIN (ENCRYPTED )?PRIVATE KEY-----(\n|\\n)MII[A-Z0-9=+\/]{20,}/ ascii wide nocase
        $pkcs8_1 = /[A-Z0-9=+\/]{4}(\n|\\n)-----END (ENCRYPTED )?PRIVATE KEY-----/ ascii wide nocase

    condition:
        ($pkcs8_0 or $pkcs8_1)
}
