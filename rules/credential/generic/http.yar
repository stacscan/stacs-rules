rule CredentialGenericHTTPBasic : Credential Generic HTTP {

    meta:
        name        = "HTTP Basic Authentication"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 70
        description = "Potential HTTP basic authentication credentials found."

    strings:
        $atom_0 = "http://" ascii wide private
        $atom_1 = "https://" ascii wide private

        $ascii_1 = /\bhttps?:\/\/[a-zA-Z0-9@\-_.%]{1,256}:[\x21-\x7E]{1,256}@[a-zA-Z0-9\-.]+(\/|\b)/ ascii wide
    
    condition:
        (any of ($atom_*)) and (any of ($ascii_*))
}
