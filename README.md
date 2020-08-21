pcsc
=====

Erlang binding for `libpcsc` (the PC/SC smartcard interface library). This
allows you to talk to smartcard devices from Erlang at a low level (sending
ISO7816 APDUs etc).

Examples
--------

Listing readers and their states, monitoring for changes:

    1> pcsc_card_db:list_readers().
    {ok,[<<"Yubico YubiKey OTP+FIDO+CCID 00 00">>,
         <<"Alcor Micro AU9560 01 00">>,
         <<"ACS ACR122U PICC Interface 02 00">>]}

    2> pcsc_card_db:get_reader_state(<<"ACS ACR122U PICC Interface 02 00">>).
    {ok,[empty]}

    3> pcsc_card_db:monitor_cards(#{in_reader => #{name_contains => <<"ACS">>}}).
    {ok,#Ref<0.2854622174.861143041.134395>}

    4> flush().
    ok

    5> flush().
    Shell got {pcsc_card,inserted,#Ref<0.2854622174.861143041.134395>,
                         <<"ACS ACR122U PICC Interface 02 00">>,
                         <<59,128,128,1,1>>}
    ok

    6> flush().
    Shell got {pcsc_card,removed,#Ref<0.2854622174.861143041.134395>,
                         <<"ACS ACR122U PICC Interface 02 00">>}
    ok

Built-in ATR parser for any needed information:

    7> iso7816:decode_atr(<<59,128,128,1,1>>).
    #{di => 1,fi => 372,fmax => 5,guardn => 0,
      historical_bytes => {proprietary,<<>>},
      t0 => #{wi => 10},
      t1 => #{bwi => 4,checksum => lrc,cwi => 13,ifsc => 32}}

Connect to a card in a particular reader and carry out a transaction (in this
case selecting the NIST PIV applet by short AID):

    8> {ok, Card} = pcsc_card:start_link(
    8>    <<"ACS ACR122U PICC Interface 02 00">>,
    8>    shared, [t1, t0]).
    {ok,<0.627.0>}

    9> ok = pcsc_card:begin_transaction(Card),
    9> {ok, Replies} = pcsc_card:command(Card,
    9>     #apdu_cmd{cla = iso, ins = select, p1 = 4, p2 = 0, data = PIVAid}),
    9> ok = pcsc_card:end_transaction(Card).
    ok

Basic tools for decoding and encoding BER-TLV format:

    10> Replies.
    [#apdu_reply{proto = t1,sw = ok,
             data = <<97,58,79,11,160,0,0,3,8,0,0,16,0,1,0,121,13,79,
                      11,160,0,0,3,8,...>>}]

    11> [#apdu_reply{data = D}] = Replies.
    [#apdu_reply{proto = t1,sw = ok,
                data = <<97,58,79,11,160,0,0,3,8,0,0,16,0,1,0,121,13,79,
                        11,160,0,0,3,8,...>>}]

    12> {ok, [ {16#61, D1} ]} = iso7816:decode_ber_tlvs(D).
    {ok,[{97,
        <<79,11,160,0,0,3,8,0,0,16,0,1,0,121,13,79,11,160,0,0,
            3,8,0,0,...>>}]}

    13> iso7816:decode_ber_tlvs(D1).
    {ok,[{79,<<160,0,0,3,8,0,0,16,0,1,0>>},
        {121,<<79,11,160,0,0,3,8,0,0,16,0,1,0>>},
        {80,<<"PivApplet">>},
        {172,<<128,1,3,128,1,6,128,1,7,128,1,17,128,1,20,6,0>>}]}

Also includes built-in filters for managing ISO7816 command and response
chaining, and a filter for control commands built-in to ACR122U NFC readers
and its clones (see the API docs).

Installing
----------

Available on [hex.pm](https://hex.pm/packages/pcsc)

API docs
--------

[Edoc](https://arekinath.github.io/erlang-pcsc/index.html)
