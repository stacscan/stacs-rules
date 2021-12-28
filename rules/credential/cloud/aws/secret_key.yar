rule CredentialCloudAWSSecretKey : Credential Cloud AWS {

    meta:
        name        = "AWS Secret Key"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 80
        description = "Potential AWS Secret key found."

    strings:
        $ascii_0 = /(\"|\'|=|\s+|,|`|;|\x00|^)(AKIA|ASIA)[0-9A-Z]{16}(\"|\'|=|\s+|,|`|;|\x00|$)/ ascii wide
        $ascii_1 = /(\"|\'|=|\s+|,|`|;|\x00|^)[A-Za-z0-9+\/=]{40}(\"|\'|=|\s+|,|`|;|\x00|$)/ ascii wide
    
    condition:
        $ascii_0 and $ascii_1
}
