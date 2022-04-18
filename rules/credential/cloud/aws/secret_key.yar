rule CredentialCloudAWSSecretKey : Credential Cloud AWS {

    meta:
        name        = "AWS Secret Key"
        author      = "Peter Adkins"
        version     = "0.5.0"
        accuracy    = 80
        description = "Potential AWS Secret key found."

    strings:
        $atom_0   = "AKIA" ascii wide private
        $atom_1   = "ASIA" ascii wide private

        $access_0 = /(AKIA|ASIA)[0-9A-Z]{16}/ fullword ascii wide private
        $secret_0 = /[A-Za-z0-9\+\/=]{40}/ fullword ascii wide

    condition:
        (any of ($atom_*) and $access_0) and ($secret_0)
}
