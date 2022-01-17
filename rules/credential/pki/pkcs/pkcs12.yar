rule CredentialPKIPKCS12 : Credential PKI PKCS PKCS12 {

    meta:
        name        = "Private key (PKCS#12 / PFX)"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential private key (PKCS#12 / PFX)  found."

    strings:
        $pkcs12_keybag_bin_0 = { 06 0B 2A 86 48 86 F7 0D 01 0C 0A 01 02 }   // 1.2.840.113549.1.12.10.1.2
        $pkcs12_keyid_bin_0  = { 06 09 2A 86 48 86 F7 0D 01 09 15 } private // 1.2.840.113549.1.9.21

    condition:
        any of them
}
