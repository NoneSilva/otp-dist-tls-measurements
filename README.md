# otp-dist-tls-measurements

What `-proto_dist inet_tls` protects in Erlang distribution, and what it does
not, measured. One TLS-distributed node that requires a client certificate,
and a row per kind of peer that tries to connect to it: with or without a
certificate, from the cluster's roots or from rogue ones, with the right or the
wrong cookie, over TLS or plain TCP. A plain `inet_tcp` node and a TLS node with
`verify_none` are the controls, and one more TLS node is bound to loopback with
`inet_dist_use_interface` to show that the bind is a separate control.

Companion to [otp-loopback-node-measurements](https://github.com/erts-sched/otp-loopback-node-measurements)
(where the node listens) and to the documentation change proposed in
[erlang/otp#11617](https://github.com/erlang/otp/pull/11617). Together they
separate the three controls people conflate: the cookie, the bind address, and
TLS.

## Run it

Requirements: Docker. Nothing runs on the host: the escript refuses to start
outside a container, because its peers listen on every interface, register with
the `epmd` on 4369 and write private keys under `/tmp`. Nothing shells out
inside the container either: certificates come from
`public_key:pkix_test_data/1`, the peer nodes from the OTP `peer` module, and
every result is read inside the peer over `peer:call/4`
(`net_kernel:connect_node/1` directly; the listener list, `inet:sockname/1` over
`erlang:ports/0`, through `erl_eval`, since a fun cannot be sent to another
node). The cookie is random per run.

```text
./run-docker.sh 27 28 29
```

Each run starts an official `erlang:<version>` container on Docker's default
bridge network (its own network namespace, where the host's firewall rules do
not apply) and runs `dist_tls.escript`. Outputs are in [`results/`](results/).

## Cases and results

Identical on OTP 27.3.4.17 (erts 15.2.7.13), 28.5.0.6 (erts 16.4.0.6) and
29.0.6 (erts 17.0.6): every row has the same outcome. The outputs print the
major release and the erts version; the erts version identifies the patch
release (`otp_versions.table` in the OTP repository). The outputs differ only in
the OTP source lines quoted inside the TLS alerts (`tls_handshake_1_3.erl`,
`ssl_handshake.erl` and `tls_record.erl` move between releases) and in where
an asynchronous log line lands relative to the result line. The TLS alert or
error report that explains each refusal is in the outputs.

| Peer trying to connect | A. plain `inet_tcp` | B. `inet_tls`, `verify_peer` + `fail_if_no_peer_cert` | C. `inet_tls`, `verify_none` |
|---|---|---|---|
| cookie ok, no client certificate | **accepted** | refused: TLS alert `Certificate Required`, before the cookie is checked | **accepted** |
| cookie ok, client certificate from the cluster roots | n/a | **accepted** | n/a |
| cookie ok, client certificate from rogue roots | n/a | refused: TLS alert `Unknown CA` | n/a |
| wrong cookie, valid client certificate | n/a | refused: `Invalid challenge reply` (the cookie is still checked, after TLS) | n/a |
| wrong cookie, no client certificate | refused: `Invalid challenge reply` | n/a | refused: `Invalid challenge reply` |
| cookie ok, plain `inet_tcp` peer against the TLS node | n/a | refused: `unsupported_record_type` | n/a |
| where the node listens | `0.0.0.0:P` | `0.0.0.0:P` | `0.0.0.0:P` |

B2, the TLS node of column B started with
`-kernel inet_dist_use_interface {127,0,0,1}`: it listens on `127.0.0.1:P`, and
a loopback peer with the cluster certificate is accepted. The parameter applies
to `inet_tls` unchanged.

What the rows establish:

1. With plain `inet_tcp` the cookie is the only authentication, and it is a
   bearer check: whoever presents it is a full peer. (`net_kernel:allow/1` adds
   a node-name allow-list on top; it filters names and authenticates nothing.)
2. With `inet_tls`, `verify_peer` and `fail_if_no_peer_cert`, the client
   certificate is the authentication. A peer without a certificate, or with one
   from other roots, is refused during the TLS handshake, before the cookie is
   ever examined. The cookie is still checked afterwards, so both are required.
   Any certificate issued by the trusted roots is accepted: by default the
   certificate is not tied to the node name or address, so "who may join" is
   whoever those roots have signed.
3. With `verify_none` on the server the node is back to cookie-only
   authentication. TLS then encrypts the wire but authenticates nobody; the
   configuration looks secure and is not.
4. TLS does not change where the node listens. The listener stays on
   `0.0.0.0`; binding it to loopback is a separate control,
   `inet_dist_use_interface`, and B2 shows it applies to `inet_tls` unchanged.

## How the certificates and peers are made

`public_key:pkix_test_data/1` produces, in memory, two self-signed roots
(`SERVER ROOT CA`, which signs the server certificate, and `CLIENT ROOT CA`,
which signs the client certificate) and a `cacerts` bundle holding both;
`ca.pem` is that bundle, so "the cluster roots" in the table is this pair. It
is called twice; the second call's pair plays the rogue roots. The PEM files
(mode 0600) and the `-ssl_dist_optfile` files are written to a private
directory under `/tmp` inside the container and deleted at the end. Peers are
started with `peer:start/1` using `connection => standard_io`, so the
controlling escript needs no distribution of its own; each peer gets
`-setcookie`, and for TLS `-proto_dist inet_tls -ssl_dist_optfile <file>`.
The client side of every TLS peer uses `verify_none`: the experiment is about
the server authenticating the peer, and a real deployment would verify in both
directions.

## Not measured, and why

- TLS 1.3 post-handshake client authentication. OTP's `ssl` does not
  implement it (listed as not supported in
  `lib/ssl/doc/guides/standards_compliance.md`, RFC 8446 sections 4.2.6 and
  4.6.2; tracked in [erlang/otp#9667](https://github.com/erlang/otp/issues/9667)),
  so a node cannot accept a connection first and ask for the certificate later.
- A second physical host. The peers run in the same container; the listener's
  bind address is what determines reachability from elsewhere, and that is the
  subject of the companion repository.
- Windows and macOS. Linux containers only.

License: MIT.
