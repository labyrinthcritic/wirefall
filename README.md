# wirefall

Wirefall is a netfilter configuration frontend for creating firewalls on Linux. It's like UFW, but declarative.

A configuration is a TOML file, and looks like..

```toml
[default]
allow-incoming = false
allow-outgoing = true

# HTTP
[[incoming.rule]]
match = { tcp-port = 80 }
allow = true
```

Apply your configuration with `wirefall apply <PATH>`.
This example will allow inbound TCP connections on port 80, and block other inbound connections.

(Wirefall will attempt to read from `/etc/wirefall/wirefall.toml` if no path is provided.)

By default, Wirefall will also allow inbound packets from the loopback device (`lo`), as well as packets with the `established` or `related` conntrack state.
This is necessary for receiving any responses to outbound connections! See [examples/default.toml](examples/default.toml) to change this behavior.
