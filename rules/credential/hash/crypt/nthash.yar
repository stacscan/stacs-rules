rule CredentialHashNTHASH : Credential Hash NTHASH {

    meta:
        name        = "NTHASH (crypt format) found"
        author      = "Peter Adkins"
        version     = "0.1.1"
        accuracy    = 100
        description = "File contains an NTHASH (crypt format) which may be a credential."

    strings:
        // Based on libxcrypt's "crypt-nthash.c" Other implementations may deviate from
        // these constructs.
        $ascii_0 = /\$3\$\$[0-9a-f]{32}/ fullword ascii wide

    condition:
        any of them
}
