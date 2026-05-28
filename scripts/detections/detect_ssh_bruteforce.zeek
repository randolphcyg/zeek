# ScriptID: DETECT_SSH_BRTFORCE_v1
# Type: detection
# Category: brute_force
# Description: Detect repeated SSH password guessing using Zeek SSH bruteforce policy logic.
# Signature: A source exceeds the configured SSH password-guessing threshold.
# NoticeTypes: SSH::Password_Guessing
# Enabled: true

@load protocols/ssh/detect-bruteforcing

# Tunable threshold for offline analysis.
redef SSH::password_guesses_limit = 10;
redef SSH::guessing_timeout = 30 mins;

# Detection logic.
hook Notice::policy(n: Notice::Info) {
    if ( n$note == SSH::Password_Guessing ) {
        # Script configuration.
        add n$actions[Notice::ACTION_LOG];
    }
}