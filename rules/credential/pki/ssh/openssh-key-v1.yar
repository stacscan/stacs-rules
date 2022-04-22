rule CredentialPKISSHOpenSSHv1 : Credential PKI SSH {

    meta:
        name        = "OpenSSH v1 format private key"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential OpenSSH v1 format private key found."

    strings:
        $atom_0      = "OPENSSH PRIVATE KEY" ascii wide private
        $atom_1      = "OPENSSH PRIVATE KEY" base64 base64wide private

        $ascii_v1_0  = /-----BEGIN OPENSSH PRIVATE KEY-----(\n|\\n)b3BlbnNzaC1rZXk[A-Za-z0-9=+\/]{20}/ ascii wide

        // Occasionally, PEM private keys will be encoded as Base64 - despite them
        // already being base64 encoded (LS0t...).
        $base64_v1_0 = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk" base64 base64wide

    condition:
        $atom_0 and (any of ($ascii_*)) or $atom_1 and (any of ($base64_*))
}
