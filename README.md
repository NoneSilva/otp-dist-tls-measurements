# otp-dist-tls-measurements
Measurements of what -proto_dist inet_tls protects in Erlang distribution: verify_peer makes the client certificate the authentication (checked before the cookie), verify_none falls back to cookie-only, and TLS does not move the listener off 0.0.0.0; native certs, Docker, OTP 27.
