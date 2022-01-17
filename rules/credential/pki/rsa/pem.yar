rule CredentialPKIPEMRSA : Credential PKI PEM {

    meta:
        name        = "PEM format private key (RSA)"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential PEM format RSA private key found."

    strings:
        $ascii_pkcs1_0 = /-----BEGIN RSA PRIVATE KEY-----(\n|\\n)MII[A-Z0-9=+\/]{20,}/ ascii wide nocase
        $ascii_pkcs1_1 = /-----BEGIN RSA ENCRYPTED PRIVATE KEY-----(\n|\\n)Proc-Type:\s*4,/ ascii wide nocase
        $ascii_pkcs1_2 = /-----BEGIN RSA PRIVATE KEY-----(\n|\\n)Proc-Type:\s*4,/ ascii wide nocase

        // Occasionally, PEM private keys will be encoded as Base64 - despite them
        // already being base64 encoded (LS0t...).
        $base64_pkcs1_0 = "-----BEGIN RSA PRIVATE KEY-----\nMII" base64 base64wide

    condition:
        any of them
}
