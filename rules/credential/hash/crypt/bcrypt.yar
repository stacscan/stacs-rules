rule CredentialHashBcrypt : Credential Hash bcrypt {

    meta:
        name        = "bcrypt hash found"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "File contains an bcrypt hash which may be a credential."

    strings:
        // Based on libxcrypt's "crypt-bcrypt.c" Other implementations may deviate from
        // these constructs.
        $ascii_0 = /\$2(a|b|x|y)?\$[0-9]{2}\$[0-9A-Z\.\/]{22}[0-9A-Z\.\/]{31}/ ascii wide nocase

    condition:
        any of them
}
