use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use fcae_firefox::{Account, Accounts, ChallengeService, ControlPlane, Dialer, FirefoxError, Fxa, LoginOutcome, Result, TransportPreference};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::{mpsc, OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

use super::{captcha_solver, protect_callback};

struct JobSnapshot {
    status: &'static str,
    json: Arc<str>,
    cancel_on_release: bool,
    abort: Option<AbortHandle>,
}

impl JobSnapshot {
    fn new(id: u64, status: &'static str, result: Value, cancel_on_release: bool) -> Self {
        let json: Arc<str> = json!({"id": id, "status": status, "result": result}).to_string().into();
        Self { status, json, cancel_on_release, abort: None }
    }
}

type Services = Arc<tokio::sync::Mutex<HashMap<String, Arc<OnceCell<Accounts>>>>>;

struct Command {
    id: u64,
    request: Zeroizing<String>,
    cancel_on_release: bool,
    _permit: OwnedSemaphorePermit,
}

struct Dispatcher {
    sender: mpsc::Sender<Command>,
    permits: Arc<Semaphore>,
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

pub fn captcha_rgba(id: u64) -> Option<(u32, u32, Vec<u8>)> {
    decode_captcha_rgba(&captcha_image(id)?)
}

fn decode_captcha_rgba(data: &str) -> Option<(u32, u32, Vec<u8>)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use image::{ImageFormat, ImageReader, Limits};
    use std::io::Cursor;

    if data.len() > 8 * 1024 * 1024 { return None; }
    let (prefix, payload) = data.split_once(',')?;
    let format = match prefix {
        "data:image/png;base64" => ImageFormat::Png,
        "data:image/jpeg;base64" => ImageFormat::Jpeg,
        "data:image/gif;base64" => ImageFormat::Gif,
        "data:image/webp;base64" => ImageFormat::WebP,
        _ => return None,
    };
    let bytes = STANDARD.decode(payload).ok()?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(2048);
    limits.max_image_height = Some(2048);
    limits.max_alloc = Some(32 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    if width == 0 || height == 0 || width > 2048 || height > 2048 { return None; }
    Some((width, height, image.into_raw()))
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
        let (sender, receiver) = mpsc::channel(32);
        let permits = Arc::new(Semaphore::new(32));
        let jobs = Arc::new(Mutex::new(HashMap::new()));
        let worker_jobs = jobs.clone();
        std::thread::Builder::new()
            .name("fcae-firefox-accounts".into())
            .spawn(move || account_worker(receiver, worker_jobs))
            .expect("failed to spawn Firefox account worker");
        Dispatcher { sender, permits, jobs }
    });
    if request.len() > 64 * 1024 { return 0; }
    let Ok(permit) = dispatcher.permits.clone().try_acquire_owned() else { return 0 };
    let cancel_on_release = serde_json::from_str::<Value>(request).ok()
        .and_then(|value| value.get("op").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|op| matches!(op.as_str(), "list" | "locations_cached" | "locations"));
    let id = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    {
        let mut jobs = dispatcher.jobs.lock();
        if jobs.len() >= 128 {
            let completed: Vec<_> = jobs.iter().filter(|(_, job)| job.status != "running").map(|(id, _)| *id).collect();
            for id in completed.into_iter().take(jobs.len().saturating_sub(127)) { jobs.remove(&id); }
        }
        jobs.insert(id, JobSnapshot::new(id, "running", json!({}), cancel_on_release));
    }
    let command = Command { id, request: Zeroizing::new(request.to_string()), cancel_on_release, _permit: permit };
    if dispatcher.sender.try_send(command).is_err() {
        finish(&dispatcher.jobs, id, Err(FirefoxError::Internal("Firefox account worker is unavailable or busy".into())));
    }
    id
}

pub fn poll(id: u64) -> Option<Arc<str>> {
    DISPATCHER.get().and_then(|dispatcher| dispatcher.jobs.lock().get(&id).map(|job| job.json.clone()))
}

pub fn release(id: u64) {
    if let Some(dispatcher) = DISPATCHER.get() {
        release_job(&dispatcher.jobs, id);
    }
}

fn release_job(jobs: &Mutex<HashMap<u64, JobSnapshot>>, id: u64) {
    if let Some(job) = jobs.lock().remove(&id) {
        if job.cancel_on_release {
            if let Some(abort) = job.abort { abort.abort(); }
        }
    }
}

fn account_worker(mut receiver: mpsc::Receiver<Command>, jobs: Arc<Mutex<HashMap<u64, JobSnapshot>>>) {
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
            let id = command.id;
            let cancel_on_release = command.cancel_on_release;
            let task_jobs = jobs.clone();
            let task = tokio::spawn(async move {
                let _permit = command._permit;
                let result = execute(&services, &command.request).await;
                finish(&task_jobs, id, result);
                let jobs = task_jobs;
                let mut states = jobs.lock();
                if states.len() > 128 {
                    let completed: Vec<u64> = states.iter().filter(|(_, state)| state.status != "running").map(|(id, _)| *id).collect();
                    for id in completed.into_iter().take(states.len().saturating_sub(128)) {
                        states.remove(&id);
                    }
                }
            });
            let mut states = jobs.lock();
            if let Some(state) = states.get_mut(&id) {
                if state.status == "running" { state.abort = Some(task.abort_handle()); }
            } else if cancel_on_release {
                task.abort();
            }
        }
    });
}

fn finish(jobs: &Mutex<HashMap<u64, JobSnapshot>>, id: u64, result: Result<Value>) {
    let mut states = jobs.lock();
    if let Some(state) = states.get_mut(&id) {
        let cancel_on_release = state.cancel_on_release;
        *state = match result {
            Ok(result) => JobSnapshot::new(id, "complete", result, cancel_on_release),
            Err(error) => JobSnapshot::new(id, "error", json!({"code": error.reason_code(), "message": error.to_string()}), cancel_on_release),
        };
    }
}

fn format_bytes(bytes: i64, precision: u32) -> String {
    const UNITS: [(&str, u128); 7] = [
        ("EiB", 1 << 60), ("PiB", 1 << 50),
        ("TiB", 1 << 40), ("GiB", 1 << 30),
        ("MiB", 1 << 20), ("KiB", 1 << 10), ("B", 1),
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
    let raw_transport = optional(&request, "transport").unwrap_or_else(|| "auto".into());
    let transport = TransportPreference::parse(&raw_transport)
        .ok_or_else(|| FirefoxError::InvalidConfig("invalid Firefox transport".into()))?;
    if transport == TransportPreference::H3 { return Err(FirefoxError::H3Unavailable); }
    let accounts = service(services, &data_dir, transport).await?;
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
            let usage = accounts.tokens(&id)?.usage().await.map_err(|error| {
                log::warn!("[firefox] usage refresh failed reason={}", error.reason_code());
                error
            })?;
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

async fn service(services: &Services, data_dir: &str, transport: TransportPreference) -> Result<Accounts> {
    let cell = {
        let mut services = services.lock().await;
        services.entry(data_dir.to_string()).or_insert_with(|| Arc::new(OnceCell::new())).clone()
    };
    let accounts = cell.get_or_try_init(|| async {
        let store = fcae_firefox::AccountStore::new(data_dir)?;
        let dialer = Dialer::new(None, protect_callback(), 10)?;
        let control = ControlPlane::new(dialer).with_transport(transport).with_relay_store(store.clone()).with_current_firefox_user_agent().await;
        let challenges = Arc::new(ChallengeService::new(Some(captcha_solver())));
        let fxa = Fxa::new(control.clone()).with_challenges(challenges);
        Ok::<_, FirefoxError>(Accounts::new(store, control, fxa))
    }).await?;
    accounts.set_transport(transport);
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
    fn captcha_decoder_checks_format_and_size() {
        const PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgZGL+DwABFAEG1rmmRQAAAABJRU5ErkJggg==";
        assert!(decode_captcha_rgba("data:text/html;base64,AA==").is_none());
        assert!(decode_captcha_rgba("data:image/png;base64,@@@").is_none());
        assert!(decode_captcha_rgba(&format!("data:image/png;base64,{}", "A".repeat(8 * 1024 * 1024))).is_none());
        let (width, height, pixels) = decode_captcha_rgba(PNG).unwrap();
        assert_eq!((width, height, pixels), (1, 1, vec![1, 2, 3, 255]));
    }

    #[test]
    fn quota_display_uses_reported_bytes_and_exact_exhaustion() {
        use fcae_firefox::types::Usage;
        let quota = |limit, remaining| Usage { limit, remaining, ..Usage::default() };
        assert_eq!(format_bytes(1024, 2), "1 KiB");
        assert_eq!(format_bytes(1024_i64.pow(2), 2), "1 MiB");
        assert_eq!(format_bytes(1024_i64.pow(3), 2), "1 GiB");
        let limit = 53_687_091_200_i64;
        assert_eq!(usage_display(Some(&quota(limit, limit - 60 * 1024_i64.pow(2)))), ("60 MiB / 50 GiB".into(), false));
        assert_eq!(usage_display(Some(&quota(limit, 0))), ("50 GiB / 50 GiB".into(), true));
        assert_eq!(usage_display(Some(&quota(limit, 1))), ("49.99 GiB / 50 GiB".into(), false));
        let (near_limit, exhausted) = usage_display(Some(&quota(limit + 1, 1)));
        assert_ne!(near_limit.split(" / ").next(), near_limit.split(" / ").nth(1));
        assert!(!exhausted);
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

    #[tokio::test]
    async fn release_cancels_only_safe_background_jobs() {
        let jobs = Mutex::new(HashMap::new());
        let background = tokio::spawn(std::future::pending::<()>());
        let mut safe = JobSnapshot::new(1, "running", json!({}), true);
        safe.abort = Some(background.abort_handle());
        jobs.lock().insert(1, safe);
        release_job(&jobs, 1);
        assert!(background.await.unwrap_err().is_cancelled());

        let mutating = tokio::spawn(std::future::pending::<()>());
        let mut job = JobSnapshot::new(2, "running", json!({}), false);
        job.abort = Some(mutating.abort_handle());
        jobs.lock().insert(2, job);
        release_job(&jobs, 2);
        tokio::task::yield_now().await;
        assert!(!mutating.is_finished());
        mutating.abort();
        let _ = mutating.await;
    }

    #[test]
    fn finishing_a_released_job_does_not_recreate_it() {
        let jobs = Mutex::new(HashMap::new());
        finish(&jobs, 42, Ok(json!({"ok": true})));
        assert!(jobs.lock().is_empty());
        jobs.lock().insert(43, JobSnapshot::new(43, "running", json!({}), false));
        finish(&jobs, 43, Ok(json!({"ok": true})));
        assert_eq!(jobs.lock().get(&43).unwrap().status, "complete");
        let output: Value = serde_json::from_str(&jobs.lock().get(&43).unwrap().json).unwrap();
        assert_eq!(output["id"], 43);
        assert_eq!(output["status"], "complete");
        assert_eq!(output["result"]["ok"], true);
    }
}
