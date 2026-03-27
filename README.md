A TCP server implementation built from ground up in Rust, exploring sockets, concurrency, and protocol design.
Relying on libc as interface to operating system and network.
I am not using Ai and get most information from the Linux man pages.

Compile with

```bash
make build
```

and run with

```bash
./a.out
```

Send message over TCP with

```bash
printf hello | socat - TCP:127.0.0.1:54333
```
