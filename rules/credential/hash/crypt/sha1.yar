rule CredentialHashSHA1 : Credential Hash SHA1 {

    meta:
        name        = "SHA1 crypt hash found"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "File contains a SHA1 crypt hash which may be a credential."

    strings:
        // Based on libxcrypt's "crypt-pbkdf1-sha1.c" Other implementations may deviate
        // from these constructs.
        $atom_0  = "$sha1" nocase ascii wide private

        $ascii_0 = /\$sha1\$[0-9]+\$[0-9A-Z\.\/]{0,64}\$[0-9A-Z\.\/]{20,28}/ ascii wide nocase

    condition:
        $atom_0 and $ascii_0
}
