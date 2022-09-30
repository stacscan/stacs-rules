rule CredentialHashSHA512 : Credential Hash SHA512 {

    meta:
        name        = "SHA512 crypt hash found"
        author      = "Peter Adkins"
        version     = "0.1.1"
        accuracy    = 100
        description = "File contains a SHA512 crypt hash which may be a credential."

    strings:
        // Based on libxcrypt's "crypt-sha512.c" Other implementations may deviate from
        // these constructs.
        $ascii_0 = /\$6\$[0-9A-Z\.\/]{3,16}\$[0-9A-Z\.\/]{86}/ fullword ascii wide nocase
        $ascii_1 = /\$6\$rounds=[0-9]{3,9}\$[0-9A-Z\.\/]{3,16}\$[0-9A-Z\.\/]{86}/ fullword ascii wide nocase

    condition:
        any of them
}
