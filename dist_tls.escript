#!/usr/bin/env escript
%%! -noshell
-include_lib("public_key/include/public_key.hrl").
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
    %% column D: the same server, plus net_kernel:allow/1. allowed_nodes/2 matches the
    %% client certificate's subjectAltName against the peer IP ({ip,_}) and the hosts of
    %% the allowed nodes ({dns_id,_}); the default test client cert has NO SAN. Two more
    %% client roots, each issuing one cert with a SAN, are added to the server's CA file.
    SanIp  = chain([#'Extension'{extnID = ?'id-ce-subjectAltName', extnValue = [{iPAddress, [127,0,0,1]}], critical = false}]),
    SanDns = chain([#'Extension'{extnID = ?'id-ce-subjectAltName', extnValue = [{dNSName, "127.0.0.1"}], critical = false}]),
    CAAll  = pem(Dir, "ca-all.pem", [cert(C) || C <- cacerts(Good) ++ cacerts(SanIp) ++ cacerts(SanDns)]),
    ICert  = pem(Dir, "i-cert.pem", [cert(peer_cert(client_config, SanIp))]),
    IKey   = pem(Dir, "i-key.pem",  [key(peer_key(client_config, SanIp))]),
    DCert  = pem(Dir, "d-cert.pem", [cert(peer_cert(client_config, SanDns))]),
    DKey   = pem(Dir, "d-key.pem",  [key(peer_key(client_config, SanDns))]),
    Server = [{certfile, SCert}, {keyfile, SKey}, {cacertfile, CA},
              {verify, verify_peer}, {fail_if_no_peer_cert, true}],
    ServerNoVerify = [{certfile, SCert}, {keyfile, SKey}, {cacertfile, CA}, {verify, verify_none}],
    Client = fun(Cert, Key) -> [{certfile, Cert}, {keyfile, Key}, {cacertfile, CA}, {verify, verify_none}] end,
    OptGood   = optfile(Dir, "good.conf",     Server,         Client(CCert, CKey)),
    OptNoCert = optfile(Dir, "nocert.conf",   Server,         [{cacertfile, CA}, {verify, verify_none}]),
    OptRogue  = optfile(Dir, "rogue.conf",    Server,         Client(RCert, RKey)),
    OptLax    = optfile(Dir, "noverify.conf", ServerNoVerify, [{cacertfile, CA}, {verify, verify_none}]),
    ServerAll = [{certfile, SCert}, {keyfile, SKey}, {cacertfile, CAAll},
                 {verify, verify_peer}, {fail_if_no_peer_cert, true}],
    %% the server default is fail_if_no_peer_cert = true once verify_peer is set (ssl_config.erl),
    %% so "client certificate optional" has to be said explicitly
    ServerAllOptional = [{certfile, SCert}, {keyfile, SKey}, {cacertfile, CAAll},
                        {verify, verify_peer}, {fail_if_no_peer_cert, false}],
    ServerLaxAll = [{certfile, SCert}, {keyfile, SKey}, {cacertfile, CAAll}, {verify, verify_none}],
    OptAllow    = optfile(Dir, "allow.conf",     ServerAll,         Client(CCert, CKey)),
    OptAllowOpt = optfile(Dir, "allow-opt.conf", ServerAllOptional, Client(CCert, CKey)),
    OptLaxAll   = optfile(Dir, "allow-lax.conf", ServerLaxAll,      [{cacertfile, CA}, {verify, verify_none}]),
    OptSanIp    = optfile(Dir, "san-ip.conf",    Server,            Client(ICert, IKey)),
    OptSanDns   = optfile(Dir, "san-dns.conf",   Server,            Client(DCert, DKey)),
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

    io:format("~n## B3. inet_tls + inet_dist_listen_options [{ip,{127,0,0,1}}]~n"),
    {B3P, B3N} = start(tlsbound2, GoodC, Tls(OptGood) ++ ["-kernel", "inet_dist_listen_options", "[{ip,{127,0,0,1}}]"]),
    io:format("  listener of ~s: ~s   (the ip option of inet_dist_listen_options binds it as well)~n", [B3N, listeners(B3P)]),
    try_connect("cookie ok + client cert, loopback peer",     c7, GoodC, Tls(OptGood),   B3N),
    stop(B3P),

    io:format("~n## C. inet_tls with verify_none on the server (a common misconfiguration)~n"),
    {LP, LN} = start(tlslax, GoodC, Tls(OptLax)),
    io:format("  listener of ~s: ~s~n", [LN, listeners(LP)]),
    try_connect("cookie ok + NO client cert", l1, GoodC, Tls(OptNoCert), LN),
    try_connect("WRONG cookie + NO client cert", l2, BadC, Tls(OptNoCert), LN),
    stop(LP),

    io:format("~n## D. inet_tls, verify_peer + fail_if_no_peer_cert, plus net_kernel:allow/1 on the server~n"),
    io:format("   (allowed_nodes/2 in inet_tls_dist runs on every accepted TLS connection)~n"),
    {NP, NN} = start(tlsnoallow, GoodC, Tls(OptAllow)),
    io:format("  allow list of ~s: ~p (control node)~n", [NN, peer:call(NP, net_kernel, allowed, [])]),
    try_connect("control: cluster cert WITHOUT SAN, allow list EMPTY", d0, GoodC, Tls(OptGood),  NN),
    try_connect("control: cert SAN iPAddress, allow list EMPTY",      d0b, GoodC, Tls(OptSanIp), NN),
    stop(NP),
    {AP, AN} = start(tlsallow, GoodC, Tls(OptAllow)),
    ok = peer:call(AP, net_kernel, allow, [['d1@127.0.0.1', 'd2@127.0.0.1', 'd3@127.0.0.1']]),
    io:format("  allow list of ~s: ~p~n", [AN, peer:call(AP, net_kernel, allowed, [])]),
    try_connect("node IN list, cert SAN iPAddress 127.0.0.1",  d1, GoodC, Tls(OptSanIp),  AN),
    try_connect("node IN list, cert SAN dNSName 127.0.0.1",    d2, GoodC, Tls(OptSanDns), AN),
    try_connect("node IN list, cluster cert WITHOUT SAN",      d3, GoodC, Tls(OptGood),   AN),
    try_connect("node NOT in list, cert SAN iPAddress",        d4, GoodC, Tls(OptSanIp),  AN),
    try_connect("node NOT in list, cert SAN dNSName 127.0.0.1", d8, GoodC, Tls(OptSanDns), AN),
    try_connect("node NOT in list, cluster cert WITHOUT SAN",  d5, GoodC, Tls(OptGood),   AN),
    stop(AP),
    io:format("~n## D2. same server and list, but {fail_if_no_peer_cert, false} (client certificate optional)~n"),
    {OP, ON} = start(tlsallowopt, GoodC, Tls(OptAllowOpt)),
    ok = peer:call(OP, net_kernel, allow, [['d1@127.0.0.1', 'd2@127.0.0.1', 'd3@127.0.0.1']]),
    io:format("  allow list of ~s: ~p~n", [ON, peer:call(OP, net_kernel, allowed, [])]),
    %% the refused attempt goes first: dist_util reports it after answering the peer, and
    %% the report only reaches the output if the accepting node lives a little longer
    try_connect("node NOT in list, NO client cert",            d7, GoodC, Tls(OptNoCert), ON),
    try_connect("node IN list, NO client cert",                d1, GoodC, Tls(OptNoCert), ON),
    stop(OP),

    io:format("~n## E. inet_tls with verify_none on the server, plus net_kernel:allow/1~n"),
    io:format("   (no certificate to match: the list can only filter the name the peer declares)~n"),
    {EP, EN} = start(tlslaxallow, GoodC, Tls(OptLaxAll)),
    ok = peer:call(EP, net_kernel, allow, [['d1@127.0.0.1', 'd2@127.0.0.1', 'd3@127.0.0.1']]),
    io:format("  allow list of ~s: ~p~n", [EN, peer:call(EP, net_kernel, allowed, [])]),
    try_connect("node NOT in list, NO client cert",            e2, GoodC, Tls(OptNoCert), EN),
    try_connect("node IN list, NO client cert",                d2, GoodC, Tls(OptNoCert), EN),
    stop(EP),

    ok = file:del_dir_r(Dir),
    io:format("~n=> inet_tls with verify_peer + fail_if_no_peer_cert makes the client certificate the~n"
              "   authentication: no cert, or a cert from another CA, is refused during the TLS~n"
              "   handshake, before the cookie is ever checked. The cookie is still checked after~n"
              "   TLS (wrong cookie + valid cert is refused), so both are required. Without an allow~n"
              "   list any certificate from the trusted roots is accepted: the certificate is not tied~n"
              "   to the node name (B). With net_kernel:allow/1 the server reduces the list to its hosts~n"
              "   and matches the certificate against them and against the peer address (D): a~n"
              "   certificate issued to an allowed host, or to the peer address, admits ANY node name on~n"
              "   that host or address, in the list or not; a certificate that names neither is refused~n"
              "   even for a node in the list. Without a certificate (D2, E) the list only filters the~n"
              "   name the peer declares.~n"
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
chain() -> chain([]).
chain(ClientPeerExts) ->
    K = [{key, {rsa, 2048, 17}}],
    public_key:pkix_test_data(#{server_chain => #{root => K, intermediates => [], peer => K},
                                client_chain => #{root => K, intermediates => [], peer => K ++ [{extensions, ClientPeerExts}]}}).
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
%% a rejection report is logged by the accepting node asynchronously, after it has
%% answered the peer: flush the logger before a node is stopped, and never make a
%% refused attempt the last action against an accepting node
stop(P) ->
    _ = try peer:call(P, logger_std_h, filesync, [default]) catch _:_ -> ok end,
    peer:stop(P).
%% evaluate inside the peer (an escript fun cannot be sent to another node)
listeners(P) ->
    Src = "[begin {ok, {A, Po}} = inet:sockname(X), lists:flatten(io_lib:format(\"~s:~w\", [inet:ntoa(A), Po])) end"
          " || X <- erlang:ports(), erlang:port_info(X, name) =:= {name, \"tcp_inet\"}, element(1, inet:peername(X)) =:= error].",
    {ok, Ts, _} = erl_scan:string(Src), {ok, Es} = erl_parse:parse_exprs(Ts),
    {value, V, _} = peer:call(P, erl_eval, exprs, [Es, []]),
    string:join(V, " ").
