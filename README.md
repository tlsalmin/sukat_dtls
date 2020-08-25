# A DTLS server/client library for Linux: sukat_dtls

## Warning: Broken on newest openssl

Seems there's some refactoring going on with openssl. See e.g.
https://github.com/openssl/openssl/issues/6934

DTLSv1_listen() Now doesn't continue the handshake with this
implementation. Probably not worth continuing development as openssl
DTLS doesn't seem all that serious of an effort.

## Introduction

This is a quite minimalistic DTLS library utilizing openssl.
Mostly the point is to describe how to use UDP-socket on Linux in
a way that allows separating multiple clients to separate file
descriptors. This is achieved by using SO_REUSEADDR and
SO_REUSEPORT selective and having connected-sockets in addition
to the main "listening" fd. A connected socket is "more precise",
similar to a routing scenario, which allows separating client
streams.

Note that I've developed this on OpenSSL 1.0.2q  20 Nov 2018. I can give no
guarantees of it working on earlier Openssl-versions.

## Building

Default build:
```bash
mkdir build && cd build
cmake ../ && make
```

To build unit tests, define the -Dtest=ON variable for cmake and
run the make test target after make.

## Test util: nc_dlts

nc_dtls is a test utility, similar to nc, for testing DTLS
connections. Similarly to nc it sends anything in stdin towards
the connected server / accepted client.

### Example:

Hosting netcat, and showing the server side. More verbosely to
show where listen socket ends up.

```bash
user@server ~/src/dtls_sukat/build $ ./nc_dtls -l -vv -c ../tests/certs/server_cert.pem -k ../tests/certs/server_key.pem
sukat_cert: load_certificate:194: Initialize ssl_ctx 0x618000000080 with certificate and private key
sukat_dtls: sukat_dtls_server_init:58: Created context 0x604000000750 for DTLS server on INADDR_ANY:0
dtls_nc: main:657: Hosting at: :::46342
sukat_dtls: sukat_dtls_accept:220: Accepted new fd 7 from ::ffff:10.0.0.126:54785
dtls_nc: nc_dtls_event_cb:173: Client connected from: ::ffff:10.0.0.126:54785
sukat_dtls: sukat_dtls_listen_step:141: Client 0x60d000000380 from ::ffff:10.0.0.126:54785 DTLS handshake finished
sukat_dtls: sukat_dtls_client_accept:366: Client 0x60d000000380 handshake finished
dtls_nc: nc_dtls_event_cb:173: Client established from: ::ffff:10.0.0.126:54785
Hello from client
Hello back from server
```

netcat from the client side.

```bash
client@host ~/src/sukat_dtls/build $ ./nc_dtls 10.0.0.201 46342
Hello from client
Hello back from server
```

Data visible in tshark:

```
    1 0.000000000   10.0.0.126 → 10.0.0.201   DTLS 354 Client Hello
    2 0.003301921   10.0.0.201 → 10.0.0.126   DTLSv1.2 102 Hello Verify Request
    3 0.003467836   10.0.0.126 → 10.0.0.201   DTLSv1.2 386 Client Hello
    4 0.005930788   10.0.0.201 → 10.0.0.126   DTLSv1.2 1044 Server Hello, Certificate, Server Hello Done
    5 0.006469950   10.0.0.126 → 10.0.0.201   DTLSv1.2 400 Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message
    6 0.009892113   10.0.0.201 → 10.0.0.126   DTLSv1.2 308 New Session Ticket, Change Cipher Spec, Encrypted Handshake Message
    7 7.965690007   10.0.0.126 → 10.0.0.201   DTLSv1.2 97 Application Data
    8 11.136128817   10.0.0.201 → 10.0.0.126   DTLSv1.2 102 Application Data
    9 15.669861411   10.0.0.126 → 10.0.0.201   DTLSv1.2 81 Encrypted Alert
   10 15.671338815   10.0.0.201 → 10.0.0.126   DTLSv1.2 81 Encrypted Alert
```

Example with multiple clients. Server side:

```
user@server ~/src/dtls_sukat/build $ ./nc_dtls -l 10.0.0.201 9999 -c ../tests/certs/server_cert.pe-k ../tests/certs/server_key.pem
Hello from client 2
Hello from client 3
Hello from client 1
Hello from client 8
Hello from client 6
Hello from client 18
Hello from client 16
Hello from client 13
Hello from client 10
Hello from client 17
Hello from client 15
```

Client side:
```
user@client ~/src/sukat_dtls/build $ for i in $(seq 1 20); do echo "Hello from client $i" | ./nc_dtls 10.0.0.201 9999 & done
...
```

tshark data:
```
    1 0.000000000   10.0.0.126 → 10.0.0.201   DTLS 354 Client Hello
    2 0.002627401   10.0.0.201 → 10.0.0.126   DTLSv1.2 102 Hello Verify Request
    3 0.003481598   10.0.0.126 → 10.0.0.201   DTLSv1.2 386 Client Hello
    4 0.005473779   10.0.0.201 → 10.0.0.126   DTLSv1.2 1044 Server Hello, Certificate, Server Hello Done
    5 0.008328319   10.0.0.126 → 10.0.0.201   DTLS 354 Client Hello
    6 0.009062765   10.0.0.126 → 10.0.0.201   DTLSv1.2 400 Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message
    7 0.009542738   10.0.0.201 → 10.0.0.126   DTLSv1.2 102 Hello Verify Request
    8 0.010213269   10.0.0.126 → 10.0.0.201   DTLS 354 Client Hello
    9 0.012405141   10.0.0.201 → 10.0.0.126   DTLSv1.2 308 New Session Ticket, Change Cipher Spec, Encrypted Handshake Message
   10 0.012448223   10.0.0.201 → 10.0.0.126   DTLSv1.2 102 Hello Verify Request
   11 0.013051056   10.0.0.126 → 10.0.0.201   DTLS 354 Client Hello
   12 0.013652453   10.0.0.126 → 10.0.0.201   DTLS 354 Client Hello
   13 0.014438361   10.0.0.126 → 10.0.0.201   DTLSv1.2 386 Client Hello
   14 0.014495594   10.0.0.201 → 10.0.0.126   DTLSv1.2 102 Hello Verify Request
   15 0.014519288   10.0.0.201 → 10.0.0.126   DTLSv1.2 102 Hello Verify Request
   16 0.014562802   10.0.0.126 → 10.0.0.201   DTLSv1.2 99 Application Data
   17 0.014621537   10.0.0.126 → 10.0.0.201   DTLSv1.2 81 Encrypted Alert
...
```

Shows multiple client connecting and getting properly separated. Of course not
all client connect, as this is UDP, which is lossy.

## TODO:

DTLS and MTU: Since we're not using stream-oriented sockets, the
              MTU needs to be checked and acted accordingly.
