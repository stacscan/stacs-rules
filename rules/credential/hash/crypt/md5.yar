rule CredentialHashMD5 : Credential Hash MD5 {

    meta:
        name        = "MD5 crypt hash found"
        author      = "Peter Adkins"
        version     = "0.1.1"
        accuracy    = 100
        description = "File contains an MD5 crypt hash which may be a credential."

    strings:
        // Based on libxcrypt's "crypt-sunmd5.c" Other implementations may deviate from
        // these constructs.
        $ascii_0 = /\$1\$[0-9A-Z\.\/]{0,8}\$[0-9A-Z\.\/]{22}/ fullword ascii wide nocase
        $ascii_1 = /\$md5\$[0-9A-Z\.\/]{0,8}\$[0-9A-Z\.\/]{22}/ fullword ascii wide nocase
        $ascii_2 = /\$md5\$[0-9A-Z\.\/]{0,8}\$$[0-9A-Z\.\/]{22}/ fullword ascii wide nocase
        $ascii_3 = /\$md5,rounds=[0-9]+\$[0-9A-Z\.\/]{0,8}\$(\$)?[0-9A-Z\.\/]{22}/ fullword ascii wide nocase

    condition:
        any of them
}
