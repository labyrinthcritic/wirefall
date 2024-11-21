use serde::Serialize;
use serde_json::{json, Value};

use crate::config::{Config, Matches, Rule};

pub fn construct_json(config: &Config) -> Value {
    let incoming_rules = config
        .incoming
        .rules
        .iter()
        .map(|r| rule(r, Direction::Input))
        .map(|r| json!({ "add": r }))
        .collect::<Vec<_>>();
    let outgoing_rules = config
        .outgoing
        .rules
        .iter()
        .map(|r| rule(r, Direction::Output))
        .map(|r| json!({ "add": r }))
        .collect::<Vec<_>>();

    let actions = vec![
        json!({ "flush": { "ruleset": null } }),
        json!({ "add": { "table": { "family": "inet", "name": "wirefall" } } }),
        json!({
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
        }),
        json!({
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
        }),
    ]
    .into_iter()
    .chain(incoming_rules)
    .chain(outgoing_rules)
    .collect::<Vec<_>>();

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

fn rule(rule: &Rule, direction: Direction) -> Value {
    let exprs = exprs(&rule.matches, direction, rule.allow);

    json!({
        "rule": {
            "family": "inet",
            "table": "wirefall",
            "chain": direction.chain(),
            "expr": exprs,
        }
    })
}

fn exprs(matches: &Matches, direction: Direction, allow: bool) -> Vec<Value> {
    let ipv4 = matches
        .ipv4
        .map(|addr| match_equals("ip", direction.addr(), addr));
    let tcp_port = matches
        .tcp_port
        .map(|port| match_equals("tcp", direction.port(), port));
    let udp_port = matches
        .udp_port
        .map(|port| match_equals("udp", direction.port(), port));

    let action = json!({ policy(allow): null });

    [ipv4, tcp_port, udp_port]
        .into_iter()
        .flatten()
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
