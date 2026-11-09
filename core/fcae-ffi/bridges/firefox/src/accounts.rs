use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use fcae_firefox::{Account, Accounts, ChallengeService, ControlPlane, Dialer, FirefoxError, Fxa, LoginOutcome, Result};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::{mpsc, OnceCell};

use super::{captcha_solver, protect_callback};

#[derive(Clone)]
pub struct JobSnapshot {
    pub status: &'static str,
    pub result: Value,
}

type Services = Arc<tokio::sync::Mutex<HashMap<String, Arc<OnceCell<Accounts>>>>>;

struct Command {
    id: u64,
    request: String,
}

struct Dispatcher {
    sender: mpsc::UnboundedSender<Command>,
    jobs: Arc<Mutex<HashMap<u64, JobSnapshot>>>,
}

static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();
static NEXT_JOB: AtomicU64 = AtomicU64::new(1);
static NEXT_CAPTCHA: AtomicU64 = AtomicU64::new(1);

struct CaptchaExchange {
    answer: std::sync::Mutex<Option<String>>,
    notified: tokio::sync::Notify,
}

struct CaptchaRequest {
    image: String,
    exchange: Arc<CaptchaExchange>,
}

static CAPTCHA_REQUESTS: OnceLock<Mutex<BTreeMap<u64, CaptchaRequest>>> = OnceLock::new();

fn captcha_requests() -> &'static Mutex<BTreeMap<u64, CaptchaRequest>> {
    CAPTCHA_REQUESTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct CaptchaGuard(u64);

impl Drop for CaptchaGuard {
    fn drop(&mut self) {
        captcha_requests().lock().remove(&self.0);
    }
}

pub fn captcha_pending() -> u64 {
    captcha_requests().lock().keys().next().copied().unwrap_or(0)
}

pub fn captcha_image(id: u64) -> Option<String> {
    captcha_requests().lock().get(&id).map(|request| request.image.clone())
}

pub fn captcha_answer(id: u64, answer: &str) -> bool {
    let answer = answer.trim();
    if id == 0 || answer.is_empty() || answer.len() > 256 {
        return false;
    }
    let request = captcha_requests().lock().remove(&id);
    let Some(request) = request else { return false };
    *request.exchange.answer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(answer.to_string());
    request.exchange.notified.notify_one();
    true
}

pub async fn solve_captcha(image: &str) -> Result<String> {
    let id = NEXT_CAPTCHA.fetch_add(1, Ordering::Relaxed);
    let exchange = Arc::new(CaptchaExchange {
        answer: std::sync::Mutex::new(None),
        notified: tokio::sync::Notify::new(),
    });
    {
        let mut requests = captcha_requests().lock();
        if requests.len() >= 8 {
            return Err(FirefoxError::ChallengeRequired);
        }
        requests.insert(id, CaptchaRequest { image: image.to_string(), exchange: exchange.clone() });
    }
    let _guard = CaptchaGuard(id);
    loop {
        let notified = exchange.notified.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(answer) = exchange.answer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take() {
            return Ok(answer);
        }
        notified.await;
    }
}

pub fn submit(request: &str) -> u64 {
    let dispatcher = DISPATCHER.get_or_init(|| {
        let (sender, receiver) = mpsc::unbounded_channel();
        let jobs = Arc::new(Mutex::new(HashMap::new()));
        let worker_jobs = jobs.clone();
        std::thread::Builder::new()
            .name("fcae-firefox-accounts".into())
            .spawn(move || account_worker(receiver, worker_jobs))
            .expect("failed to spawn Firefox account worker");
        Dispatcher { sender, jobs }
    });
    let id = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    dispatcher.jobs.lock().insert(id, JobSnapshot { status: "running", result: json!({}) });
    if dispatcher.sender.send(Command { id, request: request.to_string() }).is_err() {
        finish(&dispatcher.jobs, id, Err(FirefoxError::Internal("Firefox account worker is unavailable".into())));
    }
    id
}

pub fn poll(id: u64) -> Option<JobSnapshot> {
    DISPATCHER.get().and_then(|dispatcher| dispatcher.jobs.lock().get(&id).cloned())
}

pub fn release(id: u64) {
    if let Some(dispatcher) = DISPATCHER.get() {
        dispatcher.jobs.lock().remove(&id);
    }
}

fn account_worker(mut receiver: mpsc::UnboundedReceiver<Command>, jobs: Arc<Mutex<HashMap<u64, JobSnapshot>>>) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            log::error!("[firefox] cannot create account runtime: {error}");
            return;
        }
    };
    runtime.block_on(async move {
        let services: Services = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        while let Some(command) = receiver.recv().await {
            let services = services.clone();
            let jobs = jobs.clone();
            tokio::spawn(async move {
                let result = execute(&services, &command.request).await;
                finish(&jobs, command.id, result);
                let mut states = jobs.lock();
                if states.len() > 128 {
                    let completed: Vec<u64> = states.iter().filter(|(_, state)| state.status != "running").map(|(id, _)| *id).collect();
                    for id in completed.into_iter().take(states.len().saturating_sub(128)) {
                        states.remove(&id);
                    }
                }
            });
        }
    });
}

fn finish(jobs: &Mutex<HashMap<u64, JobSnapshot>>, id: u64, result: Result<Value>) {
    let snapshot = match result {
        Ok(result) => JobSnapshot { status: "complete", result },
        Err(error) => JobSnapshot {
            status: "error",
            result: json!({"code": error.reason_code(), "message": error.to_string()}),
        },
    };
    if let Some(state) = jobs.lock().get_mut(&id) {
        *state = snapshot;
    }
}

fn format_bytes(bytes: i64, precision: u32) -> String {
    const UNITS: [(&str, u128); 7] = [
        ("EB", 1_000_000_000_000_000_000), ("PB", 1_000_000_000_000_000),
        ("TB", 1_000_000_000_000), ("GB", 1_000_000_000),
        ("MB", 1_000_000), ("KB", 1_000), ("B", 1),
    ];
    let bytes = bytes.max(0) as u128;
    let &(unit, divisor) = UNITS.iter().find(|(_, divisor)| bytes >= *divisor).unwrap_or(&UNITS[6]);
    if divisor == 1 { return format!("{bytes} B"); }
    let scale = 10u128.pow(precision);
    let scaled = bytes * scale / divisor;
    let fraction = format!("{:0width$}", scaled % scale, width = precision as usize);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{} {unit}", scaled / scale)
    } else {
        format!("{}.{fraction} {unit}", scaled / scale)
    }
}

fn usage_display(usage: Option<&fcae_firefox::types::Usage>) -> (String, bool) {
    let Some(usage) = usage else { return ("Not reported".into(), false) };
    if usage.unlimited { return ("Unlimited".into(), false); }
    let limit = usage.limit.max(0);
    let used = limit.saturating_sub(usage.remaining.max(0)).clamp(0, limit);
    let exhausted = usage.exhausted();
    for precision in 2..=18 {
        let used_text = format_bytes(used, precision);
        let limit_text = format_bytes(limit, precision);
        if used == limit || used_text != limit_text {
            return (format!("{used_text} / {limit_text}"), exhausted);
        }
    }
    (format!("{used} B / {limit} B"), exhausted)
}

fn account_json(account: Account) -> Result<Value> {
    let (monthly_usage, exhausted) = usage_display(account.usage.as_ref());
    let mut value = serde_json::to_value(account)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("monthly_usage".into(), json!(monthly_usage));
        object.insert("monthly_usage_exhausted".into(), json!(exhausted));
    }
    Ok(value)
}

async fn execute(services: &Services, raw: &str) -> Result<Value> {
    let request: Value = serde_json::from_str(raw)?;
    let operation = required(&request, "op")?;
    let data_dir = optional(&request, "data_dir").unwrap_or_else(|| "fcae-data".into());
    if operation == "list" {
        let store = fcae_firefox::AccountStore::new(&data_dir)?;
        let values = store.list()?.into_iter().map(account_json).collect::<Result<Vec<_>>>()?;
        return Ok(json!({"accounts": values}));
    }
    if operation == "locations_cached" {
        let store = fcae_firefox::AccountStore::new(&data_dir)?;
        let countries = fcae_firefox::server_list::RemoteSettings::cached(&store).unwrap_or_default();
        return Ok(locations_json(countries));
    }
    let accounts = service(services, &data_dir).await?;
    match operation.as_str() {
        "locations" => {
            let countries = if request.get("refresh").and_then(Value::as_bool).unwrap_or(false) {
                accounts.refresh_locations().await?
            } else {
                accounts.locations().await?
            };
            Ok(locations_json(countries))
        }
        "login" => {
            let outcome = accounts.login(
                &required(&request, "email")?,
                &required(&request, "password")?,
                optional(&request, "unblock_code").as_deref(),
            ).await?;
            match outcome {
                LoginOutcome::Complete(account) => Ok(json!({"state":"complete", "account": account_json(account)?})),
                LoginOutcome::EmailCode(pending) => Ok(json!({"state":"email_code", "pending_id":pending.id, "email":pending.email})),
                LoginOutcome::EmailLink(pending) => Ok(json!({"state":"email_link", "pending_id":pending.id, "email":pending.email})),
                LoginOutcome::Totp(pending) => Ok(json!({"state":"totp", "pending_id":pending.id, "email":pending.email})),
                LoginOutcome::UnblockCode(prompt) => Ok(json!({"state":"unblock_code", "email":prompt.email, "sent":prompt.sent})),
            }
        }
        "verify_email" => {
            let account = accounts.verify_email(&required(&request, "pending_id")?, &required(&request, "code")?).await?;
            Ok(json!({"state":"complete", "account":account_json(account)?}))
        }
        "verify_totp" => {
            let account = accounts.verify_totp(&required(&request, "pending_id")?, &required(&request, "code")?).await?;
            Ok(json!({"state":"complete", "account":account_json(account)?}))
        }
        "confirm_email_link" => {
            let account = accounts.confirm_email_link(&required(&request, "pending_id")?).await?;
            Ok(json!({"state":"complete", "account":account_json(account)?}))
        }
        "resend" => {
            accounts.resend_email(&required(&request, "pending_id")?).await?;
            Ok(json!({"ok":true}))
        }
        "cancel" => {
            accounts.cancel_login(&required(&request, "pending_id")?).await;
            Ok(json!({"ok":true}))
        }
        "unblock" => {
            accounts.send_unblock_code(&required(&request, "email")?).await?;
            Ok(json!({"ok":true}))
        }
        "forgot" => {
            accounts.forgot_password(&required(&request, "email")?).await?;
            Ok(json!({"ok":true}))
        }
        "reset" => {
            let selected = optional(&request, "account_id");
            let removed = accounts.reset_password(&required(&request, "email")?, &required(&request, "code")?, &required(&request, "password")?).await?;
            let account_removed = selected.as_ref().is_some_and(|id| removed.contains(id));
            Ok(json!({"ok":true, "account_removed":account_removed}))
        }
        "remove" => {
            accounts.remove(&required(&request, "account_id")?).await?;
            Ok(json!({"ok":true}))
        }
        "usage" => {
            let id = required(&request, "account_id")?;
            let usage = accounts.tokens(&id)?.usage().await?;
            Ok(json!({"usage":usage, "account":account_json(accounts.store().get(&id)?)?}))
        },
        "entitlement" => {
            let entitlement = accounts.tokens(&required(&request, "account_id")?)?.entitlement().await?;
            Ok(json!({"entitlement":{
                "subscribed":entitlement.subscribed,
                "uid":entitlement.uid,
                "max_bytes":entitlement.max_bytes,
                "limited_bandwidth":entitlement.limited_bandwidth,
            }}))
        }
        "activate" => {
            let entitlement = accounts.tokens(&required(&request, "account_id")?)?.activate().await?;
            Ok(json!({"entitlement":{"subscribed":entitlement.subscribed, "uid":entitlement.uid}}))
        }
        other => Err(FirefoxError::InvalidConfig(format!("unknown Firefox account operation {other:?}"))),
    }
}

fn locations_json(mut countries: Vec<fcae_firefox::types::Country>) -> Value {
    countries.sort_by_key(|country| country.name.to_lowercase());
    let mut locations = Vec::with_capacity(countries.len() + countries.iter().map(|country| country.cities.len()).sum::<usize>());
    for country in countries {
        if country.code.eq_ignore_ascii_case(fcae_firefox::server_list::RECOMMENDED_COUNTRY) {
            continue;
        }
        let country_name = country.name.trim();
        let single_matching_city = country.cities.len() == 1
            && country.cities[0].name.trim().eq_ignore_ascii_case(country_name);
        let alias = if single_matching_city { country.cities[0].code.as_str() } else { "" };
        locations.push(json!({"value":&country.code, "label":country_name, "alias":alias}));
        if single_matching_city {
            continue;
        }
        for city in country.cities {
            if city.code.eq_ignore_ascii_case(&country.code) {
                continue;
            }
            let city_name = city.name.trim();
            let city_label = if city_name.eq_ignore_ascii_case(country_name) { &city.code } else { city_name };
            locations.push(json!({"value":&city.code, "label":format!("{} — {}", country_name, city_label)}));
        }
    }
    json!({"locations":locations})
}

async fn service(services: &Services, data_dir: &str) -> Result<Accounts> {
    let cell = {
        let mut services = services.lock().await;
        services.entry(data_dir.to_string()).or_insert_with(|| Arc::new(OnceCell::new())).clone()
    };
    let accounts = cell.get_or_try_init(|| async {
        let store = fcae_firefox::AccountStore::new(data_dir)?;
        let dialer = Dialer::new(None, protect_callback(), 10)?;
        let control = ControlPlane::new(dialer).with_current_firefox_user_agent().await;
        let challenges = Arc::new(ChallengeService::new(Some(captcha_solver())));
        let fxa = Fxa::new(control.clone()).with_challenges(challenges);
        Ok::<_, FirefoxError>(Accounts::new(store, control, fxa))
    }).await?;
    Ok(accounts.clone())
}

fn required(request: &Value, key: &str) -> Result<String> {
    optional(request, key).filter(|value| !value.is_empty())
        .ok_or_else(|| FirefoxError::InvalidConfig(format!("Firefox account request is missing {key}")))
}

fn optional(request: &Value, key: &str) -> Option<String> {
    request.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_display_uses_reported_bytes_and_exact_exhaustion() {
        use fcae_firefox::types::Usage;
        let quota = |limit, remaining| Usage { limit, remaining, ..Usage::default() };
        assert_eq!(usage_display(Some(&quota(50_000_000_000, 49_940_000_000))), ("60 MB / 50 GB".into(), false));
        assert_eq!(usage_display(Some(&quota(50_000_000_000, 0))), ("50 GB / 50 GB".into(), true));
        assert_eq!(usage_display(Some(&quota(50_000_000_000, 1))), ("49.99 GB / 50 GB".into(), false));
        assert_eq!(usage_display(Some(&quota(50_000_000_001, 1))), ("50 GB / 50.000000001 GB".into(), false));
        assert_eq!(usage_display(Some(&quota(0, 0))), ("0 B / 0 B".into(), true));
        assert_eq!(usage_display(Some(&Usage { unlimited: true, ..Usage::default() })), ("Unlimited".into(), false));
        assert_eq!(usage_display(None), ("Not reported".into(), false));
    }

    #[test]
    fn location_choices_collapse_only_equivalent_single_city() {
        use fcae_firefox::types::{City, Country};
        let city = |code: &str, name: &str| City {
            code: code.into(), name: name.into(), servers: Vec::new(),
        };
        let country = |code: &str, name: &str, cities: Vec<City>| Country {
            code: code.into(), name: name.into(), cities, locked: false, filter_expression: None,
        };
        let output = locations_json(vec![
            country("REC", "Recommended", vec![city("AUTO", "Recommended")]),
            country("DE", "Germany", vec![city("MUC", "Germany")]),
            country("US", "United States", vec![city("USX", "United States"), city("NYC", "New York")]),
            country("GB", "United Kingdom", vec![city("LON", "London")]),
        ]);
        assert_eq!(output["locations"], json!([
            {"value":"DE", "label":"Germany", "alias":"MUC"},
            {"value":"GB", "label":"United Kingdom", "alias":""},
            {"value":"LON", "label":"United Kingdom — London"},
            {"value":"US", "label":"United States", "alias":""},
            {"value":"USX", "label":"United States — USX"},
            {"value":"NYC", "label":"United States — New York"}
        ]));
    }

    #[test]
    fn finishing_a_released_job_does_not_recreate_it() {
        let jobs = Mutex::new(HashMap::new());
        finish(&jobs, 42, Ok(json!({"ok": true})));
        assert!(jobs.lock().is_empty());
        jobs.lock().insert(43, JobSnapshot { status: "running", result: json!({}) });
        finish(&jobs, 43, Ok(json!({"ok": true})));
        assert_eq!(jobs.lock().get(&43).unwrap().status, "complete");
    }
}
