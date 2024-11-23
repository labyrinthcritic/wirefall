use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "yes")]
    pub allow_loopback: bool,
    #[serde(default = "yes")]
    pub allow_established: bool,
    #[serde(default = "yes")]
    pub log: bool,

    #[serde(default)]
    pub default: DefaultBehavior,
    #[serde(default)]
    pub incoming: Chain,
    #[serde(default)]
    pub outgoing: Chain,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DefaultBehavior {
    #[serde(default = "yes")]
    pub allow_incoming: bool,
    #[serde(default = "yes")]
    pub allow_outgoing: bool,
}

impl Default for DefaultBehavior {
    fn default() -> DefaultBehavior {
        DefaultBehavior {
            allow_incoming: true,
            allow_outgoing: true,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "match")]
    pub matches: Matches,
    pub allow: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Matches {
    pub ip: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,

    pub tcp_port: Option<u16>,
    pub udp_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> OneOrMany<T> {
        OneOrMany::Many(vec![])
    }
}

impl<T> From<OneOrMany<T>> for Vec<T> {
    fn from(value: OneOrMany<T>) -> Self {
        match value {
            OneOrMany::One(t) => vec![t],
            OneOrMany::Many(vec) => vec,
        }
    }
}

fn yes() -> bool {
    true
}
