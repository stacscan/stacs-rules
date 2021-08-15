rule CredentialPKIPEMRSA : Credential PKI PEM {

    meta:
        name        = "PEM format private key (RSA)"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential PEM format RSA private key found."

    strings:
        $pkcs1_0 = /-----BEGIN RSA PRIVATE KEY-----(\n|\\n)MII[A-Z0-9=+\/]{20,}/ ascii wide nocase
        $pkcs1_1 = /-----BEGIN RSA ENCRYPTED PRIVATE KEY-----(\n|\\n)Proc-Type:\s*4,/ ascii wide nocase
        $pkcs1_2 = /[A-Z0-9=+\/]{4}(\n|\\n)-----END RSA (ENCRYPTED )?PRIVATE KEY-----/ ascii wide nocase

    condition:
        (($pkcs1_0 or $pkcs1_1) and $pkcs1_2)
}
