rule CredentialNixPasswdStatic : Credential Nix Passwd {

    meta:
        name        = "Static password in /etc/passwd"
        author      = "Peter Adkins"
        version     = "0.1.0"
        accuracy    = 100
        description = "User in /etc/passwd has been configured with a static password."

    strings:
        $ascii_0 = /^[a-z_][a-z0-9_-]+\$?:[\$0-9a-z\.\/=,]{2,}:[0-9]+:[0-9]+:.*:\/.*:\/?.*(\r|\n)+/ ascii nocase
        $ascii_1 = /(\r|\n)+[a-z_][a-z0-9_-]+\$?:[\$0-9a-z\.\/=,]{2,}:[0-9]+:[0-9]+:.*:\/.*:\/?.*(\r|\n)+/ ascii nocase
    
    condition:
        any of them
}
