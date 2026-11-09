use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use fcae_firefox::{Account, Accounts, ChallengeService, ControlPlane, Dialer, FirefoxError, Fxa, LoginOutcome, Result};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::{captcha_solver, protect_callback};

#[derive(Clone)]
pub struct JobSnapshot {
    pub status: &'static str,
    pub result: Value,
}

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
        let mut services: HashMap<String, Accounts> = HashMap::new();
        while let Some(command) = receiver.recv().await {
            let result = execute(&mut services, &command.request).await;
            finish(&jobs, command.id, result);
            let mut states = jobs.lock();
            if states.len() > 128 {
                let completed: Vec<u64> = states.iter().filter(|(_, state)| state.status != "running").map(|(id, _)| *id).collect();
                for id in completed.into_iter().take(states.len().saturating_sub(128)) {
                    states.remove(&id);
                }
            }
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
    jobs.lock().insert(id, snapshot);
}

fn format_bytes(bytes: i64) -> String {
    let value = bytes.max(0) as f64;
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    if value >= GIB {
        format!("{:.2} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.2} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{} B", value as i64)
    }
}

fn account_json(account: Account) -> Result<Value> {
    let monthly_usage = match &account.usage {
        Some(usage) if usage.unlimited => "Unlimited".into(),
        Some(usage) => {
            let used = usage.limit.saturating_sub(usage.remaining).max(0);
            format!("{} used of {}", format_bytes(used), format_bytes(usage.limit))
        }
        None => "Not reported".into(),
    };
    let mut value = serde_json::to_value(account)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("monthly_usage".into(), json!(monthly_usage));
    }
    Ok(value)
}

async fn execute(services: &mut HashMap<String, Accounts>, raw: &str) -> Result<Value> {
    let request: Value = serde_json::from_str(raw)?;
    let operation = required(&request, "op")?;
    let data_dir = optional(&request, "data_dir").unwrap_or_else(|| "fcae-data".into());
    let accounts = service(services, &data_dir).await?;
    match operation.as_str() {
        "list" => {
            let values = accounts.list()?.into_iter().map(account_json).collect::<Result<Vec<_>>>()?;
            Ok(json!({"accounts": values}))
        }
        "locations" => {
            let countries = accounts.locations().await?;
            let mut locations = Vec::with_capacity(countries.len() + countries.iter().map(|country| country.cities.len()).sum::<usize>());
            for country in countries {
                let country_name = country.name;
                locations.push(json!({"value":country.code, "label":country_name.clone()}));
                for city in country.cities {
                    locations.push(json!({"value":city.code, "label":format!("{} — {}", country_name, city.name)}));
                }
            }
            Ok(json!({"locations":locations}))
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
        "usage" => Ok(json!({"usage":accounts.tokens(&required(&request, "account_id")?)?.usage().await?})),
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

async fn service<'a>(services: &'a mut HashMap<String, Accounts>, data_dir: &str) -> Result<&'a Accounts> {
    if !services.contains_key(data_dir) {
        let store = fcae_firefox::AccountStore::new(data_dir)?;
        let dialer = Dialer::new(None, protect_callback(), 10)?;
        let control = ControlPlane::new(dialer).with_current_firefox_user_agent().await;
        let challenges = Arc::new(ChallengeService::new(Some(captcha_solver())));
        let fxa = Fxa::new(control.clone()).with_challenges(challenges);
        services.insert(data_dir.to_string(), Accounts::new(store, control, fxa));
    }
    Ok(services.get(data_dir).unwrap())
}

fn required(request: &Value, key: &str) -> Result<String> {
    optional(request, key).filter(|value| !value.is_empty())
        .ok_or_else(|| FirefoxError::InvalidConfig(format!("Firefox account request is missing {key}")))
}

fn optional(request: &Value, key: &str) -> Option<String> {
    request.get(key).and_then(Value::as_str).map(str::to_string)
}
