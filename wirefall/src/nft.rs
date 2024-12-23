use serde::Serialize;
use serde_json::{json, Value};

use crate::config::{Config, Matches, Rule};

const LOG_PREFIX: &str = "[wirefall] denied: ";

pub fn actions(config: &Config) -> Vec<Value> {
    let incoming_rules = config
        .incoming
        .rules
        .iter()
        .map(|r| rule(r, Direction::Input, config.log))
        .map(|r| json!({ "add": r }))
        .collect::<Vec<_>>();
    let outgoing_rules = config
        .outgoing
        .rules
        .iter()
        .map(|r| rule(r, Direction::Output, config.log))
        .map(|r| json!({ "add": r }))
        .collect::<Vec<_>>();

    let mut lo_ct = Vec::new();

    if config.allow_loopback {
        lo_ct.push(json!({ "add": allow_loopback() }));
    }
    if config.allow_established {
        lo_ct.push(json!({ "add": allow_establish_connections() }));
    }

    let flush_ruleset = json!({ "flush": { "ruleset": null } });
    let add_table = json!({ "add": { "table": { "family": "inet", "name": "wirefall" } } });
    let add_input_chain = json!({
        "add": {
            "chain": {
                "type": "filter",
                "family": "inet",
                "table": "wirefall",
                "name": "input",
                "hook": "input",
                "prio": 0,
                "policy": policy(config.default.allow_incoming),
            },
        },
    });
    let add_output_chain = json!({
        "add": {
            "chain": {
                "type": "filter",
                "family": "inet",
                "table": "wirefall",
                "name": "output",
                "hook": "output",
                "prio": 0,
                "policy": policy(config.default.allow_outgoing),
            },
        },
    });

    let logs = if config.log {
        [
            ("input", config.default.allow_incoming),
            ("output", config.default.allow_outgoing),
        ]
        .into_iter()
        .filter_map(|(chain, allow)| {
            let add = json!({
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "wirefall",
                        "chain": chain,
                        "expr": [
                            {
                                "log": { "prefix": LOG_PREFIX },
                            },
                        ],
                    },
                },
            });
            Some(add).filter(|_| !allow)
        })
        .collect()
    } else {
        vec![]
    };

    vec![flush_ruleset, add_table, add_input_chain, add_output_chain]
        .into_iter()
        .chain(lo_ct)
        .chain(incoming_rules)
        .chain(outgoing_rules)
        .chain(logs)
        .collect::<Vec<_>>()
}

pub fn payload(actions: Vec<Value>) -> Value {
    json!({ "nftables": actions })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Input,
    Output,
}

impl Direction {
    fn chain(&self) -> &'static str {
        match self {
            Direction::Input => "input",
            Direction::Output => "output",
        }
    }

    fn addr(&self) -> &'static str {
        match self {
            Direction::Input => "saddr",
            Direction::Output => "daddr",
        }
    }

    fn port(&self) -> &'static str {
        match self {
            Direction::Input => "dport",
            Direction::Output => "sport",
        }
    }
}

fn policy(allow: bool) -> String {
    if allow { "accept" } else { "drop" }.to_string()
}

/// Construct a rule value.
fn rule(rule: &Rule, direction: Direction, log: bool) -> Value {
    let exprs = exprs(&rule.matches, direction, rule.allow, log);

    json!({
        "rule": {
            "family": "inet",
            "table": "wirefall",
            "chain": direction.chain(),
            "expr": exprs,
        }
    })
}

/// Construct the `exprs` value for a rule.
fn exprs(matches: &Matches, direction: Direction, allow: bool, log: bool) -> Vec<Value> {
    let ipv4 = matches
        .ip
        .map(|addr| match_equals("ip", direction.addr(), addr));
    let ipv6 = matches
        .ipv6
        .map(|addr| match_equals("ip6", direction.addr(), addr));
    let tcp_port = matches
        .tcp_port
        .map(|port| match_equals("tcp", direction.port(), port));
    let udp_port = matches
        .udp_port
        .map(|port| match_equals("udp", direction.port(), port));

    let action = json!({ policy(allow): null });
    let logged = Some(json!({ "log": { "prefix": LOG_PREFIX } })).filter(|_| !allow && log);

    [ipv4, ipv6, tcp_port, udp_port]
        .into_iter()
        .flatten()
        .chain(logged)
        .chain(std::iter::once(action))
        .collect::<Vec<_>>()
}

fn match_equals<T: Serialize>(protocol: &str, field: &str, value: T) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {
                "payload": {
                    "protocol": protocol,
                    "field": field,
                },
            },
            "right": value,
        }
    })
}

fn allow_loopback() -> Value {
    json!({
        "rule": {
            "family": "inet",
            "table": "wirefall",
            "chain": "input",
            "expr": [
                {
                    "match": {
                        "op": "==",
                        "left": {
                            "meta": {
                                "key": "iifname",
                            },
                        },
                        "right": "lo",
                    },
                },
                {
                    "accept": null,
                },
            ],
        },
    })
}

fn allow_establish_connections() -> Value {
    json!({
        "rule": {
            "family": "inet",
            "table": "wirefall",
            "chain": "input",
            "expr": [
                {
                    "match": {
                        "op": "in",
                        "left": {
                            "ct": {
                                "key": "state",
                            },
                        },
                        "right": [
                            "established",
                            "related",
                        ],
                    },
                },
                {
                    "accept": null,
                },
            ],
        }
    })
}
