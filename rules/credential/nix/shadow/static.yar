rule CredentialNixShadowStatic : Credential Nix Shadow {

    meta:
        name        = "Static hash in /etc/shadow"
        author      = "Peter Adkins"
        version     = "0.2.0"
        accuracy    = 100
        description = "User in /etc/shadow has been configured with a static password."

    strings:
        $ascii_0 = /^[a-z_][a-z0-9_-]{1,256}\$?:[\$0-9a-z\.\/=,]{2,}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:(\r|\n)+/ ascii nocase
        $ascii_1 = /(\r|\n)+[a-z_][a-z0-9_-]{1,256}\$?:[\$0-9a-z\.\/=,]{2,}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:[0-9]{0,7}:(\r|\n)+/ ascii nocase
    
    condition:
        any of them
}
