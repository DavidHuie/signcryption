# Architecture

- Handshake to generate session ID
- Encapsulate writes within a frame

## Handshake

- Client sends `r` and `Cert_c`
- Server responds with `c := Enc_c (k, id_server)`
- Server responds with `sig := Sig_s(r, c, id_c ), Cert_s`
