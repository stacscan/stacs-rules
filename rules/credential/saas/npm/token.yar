rule CredentialSaaSNPMToken : Credential SaaS NPM {

    meta:
        name        = "NPM access token"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "Potential NPM access token found."

    strings:
        $atom_0 = "registry" ascii wide private
        $atom_1 = "_password" ascii wide private
        $atom_2 = "_authToken" ascii wide private

        $ascii_0 = /:_password('|"|\s){0,8}=('|"|\[|\s){0,64}[A-Z0-9=+\/.\-_]{9}('|"|\]){0,8}/ ascii wide nocase
        $ascii_1 = /:_authToken('|"|\s){0,8}=('|"|\[|\s){0,64}[A-Z0-9=+\/.\-_]{9}('|"|\]){0,8}/ ascii wide nocase
    
    condition:
        (any of ($atom_*)) and (any of ($ascii_*))
}
