# dirty-repo fixture

Synthetic repo containing one violation per skill, exercised through
canned scanner output (`fake-scanner.sh` → pre-recorded JSON).

Expected: at least one finding per framework, deterministic SARIF in
`expected/dirty.sarif`, exit code 1.
