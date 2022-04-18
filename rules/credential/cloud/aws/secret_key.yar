rule CredentialCloudAWSSecretKey : Credential Cloud AWS {

    meta:
        name        = "AWS Secret Key"
        author      = "Peter Adkins"
        version     = "0.4.1"
        accuracy    = 80
        description = "Potential AWS Secret key found."

    strings:
        $atom_0   = "AKIA" ascii wide private
        $atom_1   = "ASIA" ascii wide private

        $access_0 = /(\x00|\x22|\x27|=|\s|,|`|;|:|^)(AKIA|ASIA)[0-9A-Z]{16}(\x00|\x22|\x27|=|\s|,|`|;|:|$)/ ascii wide private
        $secret_0 = /(\x00|\x22|\x27|=|\s|,|`|;|:|^)[A-Za-z0-9\+\/=]{40}(\x00|\x22|\x27|=|\s|,|`|;|:|$)/ ascii wide

    condition:
        any of ($atom_*) and ($access_0 and $secret_0)
}
