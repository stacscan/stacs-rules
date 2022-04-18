rule CredentialPKIPEMDER : Credential PKI DER {

    meta:
        name        = "DER format private key (RSA)"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential DER format RSA private key found."

    strings:
        $atom_0 = { 02 01 00 02 } private    // version + next byte.
        $atom_1 = { 02 03 01 00 01 } private // e=65537

        // Per RFC8017 Appendix A.1.2 - It's possible to see exponents other than 3 and
        // 65537, but... really?
        $pkcs1_m512_bin_0  = { 30 82 01 ?? 02 01 00 02 41 00 [64] 02 03 01 00 01 }         // n=512, e=65537
        $pkcs1_m512_bin_1  = { 30 82 01 ?? 02 01 00 02 41 00 [64] 02 01 03 }               // n=512, e=3

        $pkcs1_m1024_bin_0 = { 30 82 02 ?? 02 01 00 02 81 81 00 [128] 02 03 01 00 01 }     // n=1024, e=65537
        $pkcs1_m1024_bin_1 = { 30 82 02 ?? 02 01 00 02 81 81 00 [128] 02 01 03 }           // n=1024, e=3

        $pkcs1_m2048_bin_0 = { 30 82 04 ?? 02 01 00 02 82 01 01 00 [256] 02 03 01 00 01 }  // n=2048, e=65537
        $pkcs1_m2048_bin_1 = { 30 82 04 ?? 02 01 00 02 82 01 01 00 [256] 02 01 03 }        // n=2048, e=3

        $pkcs1_m4096_bin_0 = { 30 82 09 ?? 02 01 00 02 82 02 01 00 [512] 02 03 01 00 01 }  // n=4096, e=65537
        $pkcs1_m4096_bin_1 = { 30 82 09 ?? 02 01 00 02 82 02 01 00 [512] 02 01 03 }        // n=4096, e=3

        $pkcs1_m8192_bin_0 = { 30 82 12 ?? 02 01 00 02 82 04 01 00 [1024] 02 03 01 00 01 } // n=8192, e=65537
        $pkcs1_m8192_bin_1 = { 30 82 12 ?? 02 01 00 02 82 04 01 00 [1024] 02 01 03 }       // n=8192, e=3

    condition:
        ($atom_0 and $atom_1) and (any of ($pkcs1_*))
}
