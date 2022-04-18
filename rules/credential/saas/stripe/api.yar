rule CredentialSaaSStripeAPI : Credential SaaS Stripe {

    meta:
        name        = "Stripe API Secret Key"
        author      = "Peter Adkins"
        version     = "0.4.0"
        accuracy    = 80
        description = "Potential Stripe API secret key found."

    strings:
        $atom_0  = "sk_live_" ascii wide
        $atom_1  = "sk_test_" ascii wide

        $ascii_0 = /sk_live_[0-9A-Z]{10,247}/ fullword ascii wide nocase
        $ascii_1 = /sk_test_[0-9A-Z]{10,247}/ fullword ascii wide nocase
    
    condition:
        (any of ($atom_*)) and (any of ($ascii_*))
}
