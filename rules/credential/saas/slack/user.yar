rule CredentialSaaSSlackUserToken : Credential SaaS Slack {

    meta:
        name        = "Slack User OAuth token"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential Slack User OAuth token found."

    strings:
        $ascii_0 = /xoxp-[0-9]{4,}-[0-9]{4,}-[0-9]{4,}-[0-9a-f]{32}/ ascii wide nocase
    
    condition:
        $ascii_0
}
