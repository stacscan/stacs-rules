rule CredentialPKIPuTTYPPK : Credential PKI PuTTY {

    meta:
        name        = "PuTTY PPK format private key"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential PuTTY PPK format private key found."

    strings:
        $atom_0      = "PuTTY-User-Key-File" ascii wide private
        $atom_1      = "Private-MAC" ascii wide private
        $ascii_ppk_0 = /Public-Lines:\s{0,8}[0-9]{1,8}/ ascii wide private
        $ascii_ppk_1 = /Private-Lines:\s{0,8}[0-9]{1,8}/ ascii wide

    condition:
        ($atom_0 and $atom_1) and (any of ($ascii_*))
}
