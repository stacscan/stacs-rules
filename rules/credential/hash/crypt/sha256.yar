rule CredentialHashSHA256 : Credential Hash SHA256 {

    meta:
        name        = "SHA256 crypt hash found"
        author      = "Peter Adkins"
        version     = "0.1.1"
        accuracy    = 100
        description = "File contains a SHA256 crypt hash which may be a credential."

    strings:
        // Based on libxcrypt's "crypt-sha256.c" Other implementations may deviate from
        // these constructs.
        $ascii_0 = /\$5\$[0-9A-Z\.\/]{3,16}\$[0-9A-Z\.\/]{43}/ fullword ascii wide nocase
        $ascii_1 = /\$5\$rounds=[0-9]{3,9}\$[0-9A-Z\.\/]{3,16}\$[0-9A-Z\.\/]{43}/ fullword ascii wide nocase

    condition:
        any of them
}
