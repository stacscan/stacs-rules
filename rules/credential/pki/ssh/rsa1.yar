rule CredentialPKISSHRSA1 : Credential PKI SSH {

    meta:
        name        = "SSH RSA1 format private key"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential SSH RSA1 format private key found."

    strings:
        $atom_0 = "SSH PRIVATE KEY FILE FORMAT 1.1" ascii wide private

        // SSH PRIVATE KEY FILE FORMAT 1.1\n\x00\x00\x00\x00
        $hex_0    = {53 53 48 20 50 52 49 56 41 54 45 20 4b 45 59 20 46 49 4c 45 20 46 4f 52 4d 41 54 20 31 2e 31 0a 00 00 00 00}

    condition:
        $atom_0 and $hex_0
}
