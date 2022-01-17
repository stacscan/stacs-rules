rule CredentialSaaSStripeAPI : Credential SaaS Stripe {

    meta:
        name        = "Stripe API Secret Key"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 80
        description = "Potential Stripe API secret key found."

    strings:
        $ascii_0 = /(\\n|\"|\'|=|\s+|,|`|;|\x00|:|^)sk_live_[0-9A-Z]{10,247}(\\n|\"|\'|=|:|\s+|,|`|;|\x00|$)/ ascii wide nocase
        $ascii_1 = /(\\n|\"|\'|=|\s+|,|`|;|\x00|:|^)sk_test_[0-9A-Z]{10,247}(\\n|\"|\'|=|:|\s+|,|`|;|\x00|$)/ ascii wide nocase
    
    condition:
        any of them
}
