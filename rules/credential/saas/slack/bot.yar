rule CredentialSaaSSlackBotToken : Credential SaaS Slack {

    meta:
        name        = "Slack Bot OAuth token"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential Slack Bot OAuth token found."

    strings:
        $atom_0  = "xoxb-" ascii wide
        $ascii_0 = /xoxb-[0-9]{4,24}-[0-9]{4,24}-[A-Za-z0-9]{24}/ ascii wide
    
    condition:
        $atom_0 and $ascii_0
}
