rule CredentialPKIDSAPEM : Credential PKI DSA {

    meta:
        name        = "PEM format private key (DSA)"
        author      = "Peter Adkins"
        version     = "0.3.0"
        accuracy    = 100
        description = "Potential PEM format DSA private key found."

    strings:
        $atom_0        = "PRIVATE KEY" ascii wide private
        $atom_1        = "PRIVATE KEY" base64 base64wide private

        $ascii_pkcs1_0 = /-----BEGIN DSA PRIVATE KEY-----(\n|\\n)MII[A-Za-z0-9=+\/]{20}/ ascii wide
        $ascii_pkcs1_1 = /-----BEGIN DSA ENCRYPTED PRIVATE KEY-----(\n|\\n)Proc-Type:\s{0,64}4,/ ascii wide
        $ascii_pkcs1_2 = /-----BEGIN DSA PRIVATE KEY-----(\n|\\n)Proc-Type:\s{0,64}4,/ ascii wide

        // Occasionally, PEM private keys will be encoded as Base64 - despite them
        // already being base64 encoded (LS0t...).
        $base64_pkcs1_0 = "-----BEGIN DSA PRIVATE KEY-----\nMII" base64 base64wide

    condition:
        $atom_0 and (any of ($ascii_*)) or $atom_1 and (any of ($base64_*))
}
