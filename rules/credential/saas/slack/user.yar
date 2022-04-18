rule CredentialSaaSSlackUserToken : Credential SaaS Slack {

    meta:
        name        = "Slack User OAuth token"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential Slack User OAuth token found."

    strings:
        $atom_0  = "xoxp-" ascii wide
        $ascii_0 = /xoxp-[0-9]{4,24}-[0-9]{4,24}-[0-9]{4,24}-[0-9a-fA-F]{32}/ ascii wide
    
    condition:
        $atom_0 and $ascii_0
}
