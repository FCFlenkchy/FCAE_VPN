use std::cmp::Ordering;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use http::Method;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::control::{ControlPlane, ControlRequest};
use crate::error::{FirefoxError, Result};
use crate::store::AccountStore;
use crate::types::{split_authority, valid_dns_name, Candidate, Country};

pub const REMOTE_SETTINGS_URL: &str = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records";
pub const RECOMMENDED_COUNTRY: &str = "REC";
const CACHE_NAME: &str = "server-list.json";
const FIREFOX_VERSION: &str = "158.0";

#[derive(Clone)]
pub struct RemoteSettings {
    http: ControlPlane,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerListCache {
    saved_at: DateTime<Utc>,
    countries: Vec<Country>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    data: Vec<Country>,
}

impl RemoteSettings {
    pub fn new(http: ControlPlane) -> Self {
        Self { http }
    }

    pub async fn fetch(&self) -> Result<Vec<Country>> {
        let response = self.http.send(ControlRequest::new(Method::GET, REMOTE_SETTINGS_URL)?
            .header("accept", "application/json")?).await?;
        if response.status != 200 {
            return Err(FirefoxError::Http {
                host: "firefox.settings.services.mozilla.com".into(),
                status: response.status,
                errno: None,
                retry_after: response.retry_after(),
                message: response.message(),
            });
        }
        let envelope: Envelope = response.json()?;
        if envelope.data.is_empty() || envelope.data.len() > 512 {
            return Err(FirefoxError::Protocol("Remote Settings returned an invalid location count".into()));
        }
        let countries = filter_countries(envelope.data, FIREFOX_VERSION, "");
        if countries.is_empty() {
            return Err(FirefoxError::NoLocation(" after Remote Settings filtering".into()));
        }
        Ok(countries)
    }

    pub async fn load(&self, store: &AccountStore) -> Result<Vec<Country>> {
        match self.fetch().await {
            Ok(countries) => {
                let cache = ServerListCache { saved_at: Utc::now(), countries: countries.clone() };
                if let Err(error) = store.write_cache(CACHE_NAME, &cache) {
                    log::warn!("[firefox] could not cache Remote Settings locations: {error}");
                }
                Ok(countries)
            }
            Err(network_error) => match store.read_cache::<ServerListCache>(CACHE_NAME) {
                Ok(cache) if !cache.countries.is_empty() => {
                    let countries = filter_countries(cache.countries, FIREFOX_VERSION, "");
                    if countries.is_empty() { Err(network_error) } else { Ok(countries) }
                }
                _ => Err(network_error),
            },
        }
    }
}

pub fn filter_countries(countries: Vec<Country>, version: &str, client_country: &str) -> Vec<Country> {
    countries.into_iter().filter(|country| {
        if country.code.is_empty() || country.code.len() > 16 || country.cities.is_empty() || country.cities.len() > 128 {
            return false;
        }
        match country.filter_expression.as_deref().map(str::trim).filter(|expr| !expr.is_empty()) {
            None => true,
            Some(expression) => match evaluate_filter(expression, version, client_country) {
                Ok(matched) => matched,
                Err(error) => {
                    log::warn!("[firefox] dropping location {} with unsupported filter: {error}", country.code);
                    false
                }
            },
        }
    }).collect()
}

pub fn connect_candidates(countries: &[Country]) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for country in countries {
        for city in country.cities.iter().take(128) {
            for server in city.servers.iter().take(128) {
                if server.quarantined {
                    continue;
                }
                let server_port = if server.port == 0 { 443 } else { server.port };
                if server.protocols.is_empty() {
                    push_candidate(&mut candidates, country, city, &server.hostname, server_port);
                    continue;
                }
                for protocol in &server.protocols {
                    if protocol.name != "connect" || protocol.scheme.as_deref().is_some_and(|scheme| !scheme.eq_ignore_ascii_case("https")) {
                        continue;
                    }
                    let host = if protocol.host.is_empty() { &server.hostname } else { &protocol.host };
                    let port = if protocol.port == 0 { server_port } else { protocol.port };
                    push_candidate(&mut candidates, country, city, host, port);
                }
            }
        }
    }
    candidates
}

fn push_candidate(candidates: &mut Vec<Candidate>, country: &Country, city: &crate::types::City, host: &str, port: u16) {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if port == 0 || (host.parse::<IpAddr>().is_err() && !valid_dns_name(&host)) {
        return;
    }
    let candidate = Candidate {
        address: crate::types::authority(&host, port),
        host,
        port,
        country_name: country.name.clone(),
        country_code: country.code.clone(),
        city_name: city.name.clone(),
        city_code: city.code.clone(),
    };
    if !candidates.iter().any(|existing: &Candidate| existing.address.eq_ignore_ascii_case(&candidate.address)) {
        candidates.push(candidate);
    }
}

pub fn select_candidates(all: &[Candidate], location: Option<&str>, explicit_server: Option<&str>) -> Result<Vec<Candidate>> {
    if let Some(server) = explicit_server.filter(|server| !server.trim().is_empty()) {
        let (host, port) = split_authority(server, 443)
            .ok_or_else(|| FirefoxError::InvalidConfig("Firefox server must be a host or host:port".into()))?;
        let address = crate::types::authority(&host, port);
        let selected = all.iter().find(|candidate| candidate.address.eq_ignore_ascii_case(&address)).cloned().unwrap_or(Candidate {
            address,
            host,
            port,
            country_name: String::new(),
            country_code: String::new(),
            city_name: String::new(),
            city_code: String::new(),
        });
        return Ok(vec![selected]);
    }
    if all.is_empty() {
        return Err(FirefoxError::NoLocation(String::new()));
    }
    let location = location.map(str::trim).filter(|location| !location.is_empty());
    let mut matching = Vec::<Candidate>::new();
    if let Some(location) = location {
        matching.extend(all.iter().filter(|candidate| {
            candidate.location_matches(location)
                || candidate.country_name.eq_ignore_ascii_case(location)
                || candidate.city_name.eq_ignore_ascii_case(location)
                || (location.eq_ignore_ascii_case("recommended") && candidate.country_code.eq_ignore_ascii_case(RECOMMENDED_COUNTRY))
        }).cloned());
        if matching.is_empty() {
            return Err(FirefoxError::LocationUnavailable(location.into()));
        }
    } else if all.iter().any(|candidate| candidate.country_code.eq_ignore_ascii_case(RECOMMENDED_COUNTRY)) {
        matching.extend(all.iter().filter(|candidate| candidate.country_code.eq_ignore_ascii_case(RECOMMENDED_COUNTRY)).cloned());
    } else {
        let first_code = all.first().map(|candidate| candidate.country_code.to_ascii_uppercase()).unwrap_or_default();
        if all.iter().any(|candidate| candidate.country_code.to_ascii_uppercase() != first_code) {
            return Err(FirefoxError::InvalidConfig("multiple Firefox VPN countries are available; select a location".into()));
        }
        matching.extend_from_slice(all);
    }

    let first = matching.first().cloned().ok_or_else(|| FirefoxError::NoLocation(String::new()))?;
    let first_city = matching.iter().filter(|candidate| {
        candidate.country_code == first.country_code && candidate.city_code == first.city_code && candidate.city_name == first.city_name
    }).cloned().collect::<Vec<_>>();
    let mut ordered = Vec::with_capacity(matching.len());
    if let Some(selected) = first_city.choose(&mut rand::thread_rng()) {
        ordered.push(selected.clone());
    }
    for candidate in matching {
        if !ordered.contains(&candidate) {
            ordered.push(candidate);
        }
    }
    Ok(ordered)
}

fn evaluate_filter(expression: &str, version: &str, country: &str) -> Result<bool> {
    if expression.contains("||") || expression.len() > 4096 {
        return Err(FirefoxError::Protocol("unsupported Remote Settings filter".into()));
    }
    for raw in expression.split("&&") {
        let mut term = raw.trim();
        while term.starts_with('(') && term.ends_with(')') && term.len() > 2 {
            term = term[1..term.len() - 1].trim();
        }
        if let Some(rest) = term.strip_prefix("env.version") {
            if !evaluate_version_term(rest, version)? {
                return Ok(false);
            }
        } else if let Some(rest) = term.strip_prefix("env.country") {
            if !evaluate_country_term(rest, country)? {
                return Ok(false);
            }
        } else {
            return Err(FirefoxError::Protocol("unsupported Remote Settings filter term".into()));
        }
    }
    Ok(true)
}

fn evaluate_version_term(rest: &str, version: &str) -> Result<bool> {
    let rest = rest.trim_start().strip_prefix('|').ok_or_else(|| FirefoxError::Protocol("version filter needs versionCompare".into()))?.trim_start();
    let rest = rest.strip_prefix("versionCompare").ok_or_else(|| FirefoxError::Protocol("unsupported version transform".into()))?.trim_start();
    let rest = rest.strip_prefix('(').ok_or_else(|| FirefoxError::Protocol("versionCompare needs an argument".into()))?;
    let close = rest.find(')').ok_or_else(|| FirefoxError::Protocol("unterminated versionCompare".into()))?;
    let reference = parse_quoted(rest[..close].trim())?;
    let (operator, operand) = parse_comparison(rest[close + 1..].trim())?;
    let wanted = operand.parse::<i32>().map_err(|_| FirefoxError::Protocol("version comparison needs an integer result".into()))?;
    let actual = compare_versions(version, &reference) as i32;
    Ok(compare_order(actual, operator, wanted))
}

fn evaluate_country_term(rest: &str, country: &str) -> Result<bool> {
    let (operator, operand) = parse_comparison(rest.trim())?;
    let wanted = parse_quoted(operand)?;
    let equal = country.trim().eq_ignore_ascii_case(&wanted);
    match operator {
        "==" | "===" => Ok(equal),
        "!=" | "!==" => Ok(!equal),
        _ => Err(FirefoxError::Protocol("country filter supports only equality".into())),
    }
}

fn parse_comparison(input: &str) -> Result<(&str, &str)> {
    for operator in ["===", "!==", "==", "!=", "<=", ">=", "<", ">"] {
        if let Some(rest) = input.strip_prefix(operator) {
            return Ok((operator, rest.trim()));
        }
    }
    Err(FirefoxError::Protocol("missing Remote Settings comparison operator".into()))
}

fn parse_quoted(input: &str) -> Result<String> {
    if input.starts_with('"') {
        return Ok(serde_json::from_str(input)?);
    }
    let inner = input.strip_prefix('\'').and_then(|input| input.strip_suffix('\''))
        .ok_or_else(|| FirefoxError::Protocol("filter argument must be quoted".into()))?;
    if inner.contains('\'') || inner.contains('\\') {
        return Err(FirefoxError::Protocol("unsupported escaped filter argument".into()));
    }
    Ok(inner.to_string())
}

fn compare_order(actual: i32, operator: &str, wanted: i32) -> bool {
    match operator {
        "<" => actual < wanted,
        "<=" => actual <= wanted,
        ">" => actual > wanted,
        ">=" => actual >= wanted,
        "==" | "===" => actual == wanted,
        "!=" | "!==" => actual != wanted,
        _ => false,
    }
}

#[derive(Default, Debug)]
struct VersionPart {
    a: i64,
    b: String,
    has_b: bool,
    c: i64,
    d: String,
    has_d: bool,
}

pub fn compare_versions(left: &str, right: &str) -> Ordering {
    let left = left.split('.').collect::<Vec<_>>();
    let right = right.split('.').collect::<Vec<_>>();
    for index in 0..left.len().max(right.len()) {
        let a = parse_version_part(left.get(index).copied().unwrap_or(""));
        let b = parse_version_part(right.get(index).copied().unwrap_or(""));
        let ordering = a.a.cmp(&b.a)
            .then_with(|| compare_optional_string(&a.b, a.has_b, &b.b, b.has_b))
            .then_with(|| a.cmp(&b.c))
            .then_with(|| compare_optional_string(&a.d, a.has_d, &b.d, b.has_d));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn parse_version_part(part: &str) -> VersionPart {
    let mut output = VersionPart::default();
    if part.is_empty() {
        return output;
    }
    if part == "*" {
        output.a = i32::MAX as i64;
        return output;
    }
    let (number, rest) = leading_integer(part);
    output.a = number;
    if let Some(_plus) = rest.strip_prefix('+') {
        output.a = output.a.saturating_add(1);
        output.b = "pre".into();
        output.has_b = true;
        return output;
    }
    if rest.is_empty() {
        return output;
    }
    let boundary = rest.find(|c: char| c.is_ascii_digit() || c == '+' || c == '-');
    match boundary {
        None => {
            output.b = rest.into();
            output.has_b = true;
        }
        Some(0) => {
            let (number, extra) = leading_integer(rest);
            output.c = number;
            if !extra.is_empty() {
                output.d = extra.into();
                output.has_d = true;
            }
        }
        Some(index) => {
            output.b = rest[..index].into();
            output.has_b = true;
            let (number, extra) = leading_integer(&rest[index..]);
            output.c = number;
            if !extra.is_empty() {
                output.d = extra.into();
                output.has_d = true;
            }
        }
    }
    output
}

fn leading_integer(input: &str) -> (i64, &str) {
    let mut end = usize::from(input.starts_with(['+', '-']));
    let start = end;
    while input.as_bytes().get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if end == start {
        return (0, input);
    }
    (input[..end].parse().unwrap_or(0), &input[end..])
}

fn compare_optional_string(left: &str, has_left: bool, right: &str, has_right: bool) -> Ordering {
    match (has_left, has_right) {
        (false, false) => Ordering::Equal,
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (true, true) => left.cmp(right),
    }
}
