#!/usr/bin/env escript
%%! -noshell
%% What `-proto_dist inet_tls` protects in Erlang distribution, and what it does
%% not. Native only: certificates from public_key:pkix_test_data/1 (no openssl),
%% peer nodes from the OTP `peer` module (a port owned by this VM, no shell),
%% results read inside each peer over peer:call/4.
%%
%% Rows: for one TLS-distributed node that requires a client certificate
%% (verify_peer + fail_if_no_peer_cert), which peers can connect?
%%
%% Container only (run-docker.sh): the peers listen on 0.0.0.0 and register with
%% the epmd on 4369, and private keys are written under /tmp.
main(_) ->
    filelib:is_file("/.dockerenv") orelse filelib:is_file("/run/.containerenv") orelse
        begin io:format(standard_error, "dist_tls.escript: refusing to run outside a container; use ./run-docker.sh~n", []),
              halt(2) end,
    {ok, _} = application:ensure_all_started(ssl),
    Dir = "/tmp/dist_tls." ++ os:getpid(),
    ok = file:make_dir(Dir), ok = file:change_mode(Dir, 8#700),
    GoodC = cookie(), BadC = cookie(),
    io:format("environment~n  OTP ~s erts-~s~n~n", [erlang:system_info(otp_release), erlang:system_info(version)]),
    %% two independent pairs of roots (pkix_test_data makes a server root and a
    %% client root per call): the cluster's, and a rogue pair the attacker controls
    Good = chain(), Rogue = chain(),
    CA    = pem(Dir, "ca.pem",     [cert(C) || C <- cacerts(Good)]),
    SCert = pem(Dir, "s-cert.pem", [cert(peer_cert(server_config, Good))]),
    SKey  = pem(Dir, "s-key.pem",  [key(peer_key(server_config, Good))]),
    CCert = pem(Dir, "c-cert.pem", [cert(peer_cert(client_config, Good))]),
    CKey  = pem(Dir, "c-key.pem",  [key(peer_key(client_config, Good))]),
    RCert = pem(Dir, "r-cert.pem", [cert(peer_cert(client_config, Rogue))]),
    RKey  = pem(Dir, "r-key.pem",  [key(peer_key(client_config, Rogue))]),
    Server = [{certfile, SCert}, {keyfile, SKey}, {cacertfile, CA},
              {verify, verify_peer}, {fail_if_no_peer_cert, true}],
    ServerNoVerify = [{certfile, SCert}, {keyfile, SKey}, {cacertfile, CA}, {verify, verify_none}],
    Client = fun(Cert, Key) -> [{certfile, Cert}, {keyfile, Key}, {cacertfile, CA}, {verify, verify_none}] end,
    OptGood   = optfile(Dir, "good.conf",     Server,         Client(CCert, CKey)),
    OptNoCert = optfile(Dir, "nocert.conf",   Server,         [{cacertfile, CA}, {verify, verify_none}]),
    OptRogue  = optfile(Dir, "rogue.conf",    Server,         Client(RCert, RKey)),
    OptLax    = optfile(Dir, "noverify.conf", ServerNoVerify, [{cacertfile, CA}, {verify, verify_none}]),
    Tls = fun(Opt) -> ["-proto_dist", "inet_tls", "-ssl_dist_optfile", Opt] end,

    io:format("## A. baseline, plain inet_tcp distribution (cookie is the only check)~n"),
    {PlainP, PlainN} = start(plain, GoodC, []),
    io:format("  listener of ~s: ~s~n", [PlainN, listeners(PlainP)]),
    try_connect("cookie ok, plain peer", pl1, GoodC, [], PlainN),
    try_connect("WRONG cookie, plain peer", pl2, BadC, [], PlainN),
    stop(PlainP),

    io:format("~n## B. inet_tls distribution, server requires a client certificate~n"),
    {SP, SN} = start(tlssrv, GoodC, Tls(OptGood)),
    io:format("  listener of ~s: ~s   (TLS does not move the bind off 0.0.0.0)~n", [SN, listeners(SP)]),
    %% inet_tls_dist:dist_defaults/1 sets {versions, ['tlsv1.3','tlsv1.2']} when the optfile
    %% has none, the same set as ssl's own default ('supported' in ssl:versions/0)
    io:format("  TLS versions enabled by default in this OTP: ~p~n", [proplists:get_value(supported, ssl:versions())]),
    try_connect("cookie ok + client cert from the cluster CA", c1, GoodC, Tls(OptGood),   SN),
    try_connect("cookie ok + NO client cert",                 c2, GoodC, Tls(OptNoCert), SN),
    try_connect("cookie ok + client cert from a ROGUE CA",    c3, GoodC, Tls(OptRogue),  SN),
    try_connect("WRONG cookie + valid client cert",           c4, BadC,  Tls(OptGood),   SN),
    try_connect("cookie ok, plain inet_tcp peer (no TLS)",    c5, GoodC, [],             SN),
    stop(SP),

    io:format("~n## B2. inet_tls + inet_dist_use_interface {127,0,0,1}~n"),
    {BP, BN} = start(tlsbound, GoodC, Tls(OptGood) ++ ["-kernel", "inet_dist_use_interface", "{127,0,0,1}"]),
    io:format("  listener of ~s: ~s   (the parameter applies to inet_tls unchanged)~n", [BN, listeners(BP)]),
    try_connect("cookie ok + client cert, loopback peer",     c6, GoodC, Tls(OptGood),   BN),
    stop(BP),

    io:format("~n## C. inet_tls with verify_none on the server (a common misconfiguration)~n"),
    {LP, LN} = start(tlslax, GoodC, Tls(OptLax)),
    io:format("  listener of ~s: ~s~n", [LN, listeners(LP)]),
    try_connect("cookie ok + NO client cert", l1, GoodC, Tls(OptNoCert), LN),
    try_connect("WRONG cookie + NO client cert", l2, BadC, Tls(OptNoCert), LN),
    stop(LP),

    ok = file:del_dir_r(Dir),
    io:format("~n=> inet_tls with verify_peer + fail_if_no_peer_cert makes the client certificate the~n"
              "   authentication: no cert, or a cert from another CA, is refused during the TLS~n"
              "   handshake, before the cookie is ever checked. The cookie is still checked after~n"
              "   TLS (wrong cookie + valid cert is refused), so both are required. Any certificate~n"
              "   from the trusted roots is accepted: the certificate is not tied to the node name.~n"
              "=> With verify_none the cookie is again the only check: TLS then gives confidentiality~n"
              "   on the wire, not authentication of the peer.~n"
              "=> TLS does not change where the node listens: the listener stays on 0.0.0.0. Binding~n"
              "   to loopback is a separate control, inet_dist_use_interface, and it applies to~n"
              "   inet_tls unchanged (B2).~n"
              "=> Not measured here: post-handshake client authentication (TLS 1.3), which OTP ssl~n"
              "   does not implement (erlang/otp#9667); a second physical host.~n"),
    halt().

%% a random cookie per run: the peers listen on every interface of the container
cookie() -> binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16))).

%% two self-signed roots (server root, client root), one server cert, one client cert, in memory
chain() ->
    K = [{key, {rsa, 2048, 17}}],
    public_key:pkix_test_data(#{server_chain => #{root => K, intermediates => [], peer => K},
                                client_chain => #{root => K, intermediates => [], peer => K}}).
cacerts(Chain)          -> proplists:get_value(cacerts, maps:get(client_config, Chain)).
peer_cert(Side, Chain)  -> proplists:get_value(cert, maps:get(Side, Chain)).
peer_key(Side, Chain)   -> proplists:get_value(key, maps:get(Side, Chain)).
cert(Der)               -> {'Certificate', Der, not_encrypted}.
key({Type, Der})        -> {Type, Der, not_encrypted}.
pem(Dir, Name, Entries) ->
    P = filename:join(Dir, Name),
    ok = file:write_file(P, public_key:pem_encode(Entries)), ok = file:change_mode(P, 8#600),
    P.
optfile(Dir, Name, ServerOpts, ClientOpts) ->
    P = filename:join(Dir, Name),
    ok = file:write_file(P, io_lib:format("~p.~n", [[{server, ServerOpts}, {client, ClientOpts}]])),
    P.

%% a peer node on 127.0.0.1, controlled over its stdio (this VM needs no distribution)
start(Name, Cookie, Extra) ->
    {ok, P, Node} = peer:start(#{name => Name, host => "127.0.0.1", longnames => true,
                                 connection => standard_io, args => ["-setcookie", Cookie | Extra]}),
    {P, Node}.
try_connect(Label, Name, Cookie, Extra, Target) ->
    {P, _} = start(Name, Cookie, Extra),
    R = peer:call(P, net_kernel, connect_node, [Target]),
    io:format("  ~-46s -> ~p~n", [Label, R]),
    stop(P).
%% the rejection report is logged by the accepting node asynchronously: flush its
%% logger before the node is stopped, or the last report is lost
stop(P) ->
    _ = (catch peer:call(P, logger_std_h, filesync, [default])),
    peer:stop(P).
%% evaluate inside the peer (an escript fun cannot be sent to another node)
listeners(P) ->
    Src = "[begin {ok, {A, Po}} = inet:sockname(X), lists:flatten(io_lib:format(\"~s:~w\", [inet:ntoa(A), Po])) end"
          " || X <- erlang:ports(), erlang:port_info(X, name) =:= {name, \"tcp_inet\"}, element(1, inet:peername(X)) =:= error].",
    {ok, Ts, _} = erl_scan:string(Src), {ok, Es} = erl_parse:parse_exprs(Ts),
    {value, V, _} = peer:call(P, erl_eval, exprs, [Es, []]),
    string:join(V, " ").
