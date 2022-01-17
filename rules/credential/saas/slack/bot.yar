rule CredentialSaaSSlackBotToken : Credential SaaS Slack {

    meta:
        name        = "Slack Bot OAuth token"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential Slack Bot OAuth token found."

    strings:
        $ascii_0 = /xoxb-[0-9]{4,}-[0-9]{4,}-[A-Z0-9]{24}/ ascii wide nocase
    
    condition:
        $ascii_0
}
