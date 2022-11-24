rule CredentialGenericHTTPBasic : Credential Generic HTTP {

    meta:
        name        = "HTTP Basic Authentication"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 70
        description = "Potential HTTP basic authentication credentials found."

    strings:
        $atom_0 = "http://" ascii wide private
        $atom_1 = "https://" ascii wide private

        $ascii_1 = /\bhttps?:\/\/[\x20-\x7E]{1,256}:[\x20-\x7E]{1,256}@[a-zA-Z0-9\-.]+/ ascii wide
    
    condition:
        (any of ($atom_*)) and (any of ($ascii_*))
}
