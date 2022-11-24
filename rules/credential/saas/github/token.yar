rule CredentialSaaSGithubToken : Credential SaaS Github {

    meta:
        name        = "Github API token"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential Github API token found."

    strings:
        $ascii_0  = /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/ ascii wide
        $ascii_1  = /git\+https?:\/\/[0-9a-f]{40}@/ ascii wide
    
    condition:
        any of them
}
