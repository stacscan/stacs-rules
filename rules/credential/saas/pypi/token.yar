rule CredentialSaaSPyPIToken : Credential SaaS PyPI {

    meta:
        name        = "PyPI API token"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential PyPI API token found."

    strings:
        $atom_0   = "pypi-" ascii wide

        $ascii_0  = /pypi-Ag[A-Za-z0-9=+\-_]{13}/ ascii wide
        $base64_0 = "permissions" base64 base64wide private
        $base64_1 = "pypi.org" base64 base64wide private
    
    condition:
        $atom_0 and ($ascii_0 and $base64_0 and $base64_1)
}
