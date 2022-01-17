rule CredentialSaaSPyPIToken : Credential SaaS PyPI {

    meta:
        name        = "PyPI API token"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential PyPI API token found."

    strings:
        $ascii_0  = /pypi-Ag[A-Z0-9=+\-_]{13,}/ ascii wide nocase
        $base64_0 = "permissions" base64 base64wide private
        $base64_1 = "pypi.org" base64 base64wide private
    
    condition:
        all of them
}
