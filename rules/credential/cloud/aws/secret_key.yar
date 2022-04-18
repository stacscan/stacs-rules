rule CredentialCloudAWSSecretKey : Credential Cloud AWS {

    meta:
        name        = "AWS Secret Key"
        author      = "Peter Adkins"
        version     = "0.4.1"
        accuracy    = 80
        description = "Potential AWS Secret key found."

    strings:
        $atom_0 = "AKIA" ascii wide private
        $atom_1 = "ASIA" ascii wide private

        $access_0 = { (0D | 0A | 22 | 27 | 3D | 20 | 2C | 3B | 60 | 00 | 3A | 5C 6E | 5C 72) 41 (4B | 53) 49 41 [16] (0D | 0A | 22 | 27 | 3D | 20 | 2C | 3B | 60 | 00 | 3A | 5C 6E | 5C 72) } private
        $secret_0 = { (0D | 0A | 22 | 27 | 3D | 20 | 2C | 3B | 60 | 00 | 3A | 5C 6E | 5C 72) [40] (0D | 0A | 22 | 27 | 3D | 20 | 2C | 3B | 60 | 00 | 3A | 5C 6E | 5C 72) }

        $access_1 = { 41 (4B | 53) 49 41 [15] ?? } private
        $secret_1 = { (0D | 0A | 22 | 27 | 3D | 20 | 2C | 3B | 60 | 00 | 3A | 5C 6E | 5C 72) [39] ?? }
    
    condition:
        any of ($atom_*) and (
            (
                $access_0 and $secret_0
            ) or (
                $access_1 and $secret_1 in (filesize - 41..filesize)
            )
        )
}
