# HaaS Proxy

HaaS proxy is tool for redirectiong SSH session from local computer
to server of HaaS with additional information.

More information on https://haas.nic.cz

## Building
Build in debug mode
```
cargo build
```

Build in release mode
```
cargo build --release
```

Build with logging (env RUST_LOG=debug)
```
cargo build --features log
```

Build with openssl (can produce slightly smaller binary)
```
cargo build --features openssl
```

## Running

Haas proxy can be configured via env variables

* HAAS_TOKEN - your token which can be obtained from htts://haas.nic.cz/
* HAAS_SECRED_KEY - path to secret server ssh key of your proxy (optional)
* HAAS_API - base path to haas api endpoint (default https://haas.nic.cz/api)
* HAAS_LISTEN - host and port where proxy should listen (default 127.0.0.1:22)
* HAAS_SOCKET - socket where auth data should be published (optional)
* HAAS_COMMAND - command to which auth data will be passed to (optional)

Example
```
HAAS_TOKEN=<secret> HAAS_SOCKET=127.0.0.1:8888  HAAS_LISTEN=127.0.0.1:2222 cargo run
```

```
socat TCP4:127.0.0.1:8888 -  
```
