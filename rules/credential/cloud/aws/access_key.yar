rule CredentialCloudAWSAccessKey : Credential Cloud AWS {

    meta:
        name        = "AWS Access Key"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 80
        description = "Potential AWS access key found."

    strings:
        $ascii_0 = /(\"|\'|=|\s+|,|`|;|\x00|^)(AKIA|ASIA)[0-9A-Z]{16}(\"|\'|=|\s+|,|`|;|\x00|$)/ ascii wide
    
    condition:
        $ascii_0
}
