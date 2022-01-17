rule CredentialSaaSNPMToken : Credential SaaS NPM {

    meta:
        name        = "NPM access token"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "Potential NPM access token found."

    strings:
        $ascii_0 = /registry/ ascii wide private
        $ascii_1 = /npm/ ascii wide private
        $ascii_2 = /:_password('|"|\s){0,}=('|"|\[|\s){0,}[A-Z0-9=+\/.\-_]{9,}('|"|\]){0,}/ ascii wide nocase
        $ascii_3 = /:_authToken('|"|\s){0,}=('|"|\[|\s){0,}[A-Z0-9=+\/.\-_]{9,}('|"|\]){0,}/ ascii wide nocase
    
    condition:
        ($ascii_0 or $ascii_1) and ($ascii_2 or $ascii_3)
}
