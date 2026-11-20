//! Provider clients: `from_env` reads each provider's own variables, and the
//! models handed out hit the right path with the right key. Offline, against
//! a loopback mock.

#![allow(clippy::unwrap_used, reason = "test helpers")]
#![allow(unsafe_code, reason = "tests set env vars while holding ENV_LOCK")]
#![allow(
    clippy::significant_drop_tightening,
    reason = "the env guard must live for the whole test"
)]

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rune_chain::compat::{self, Preset};
use rune_chain::embed::Embedder;
use rune_chain::prelude::*;
use rune_chain::{
    azure, cerebras, cohere, deepseek, fireworks, groq, huggingface, hyperbolic, lmstudio, mistral,
    moonshot, nvidia, openrouter, sambanova, together, vllm, xai,
};
use rune_chain_core::testing::http::{MockResponse, MockServer};

const CHAT: &str =
    r#"{"choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}"#;
const EMBED: &str =
    r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5,0.25]}]}"#;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Every variable any provider reads, cleared at the start of each test.
const ALL_VARS: &[&str] = &[
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "XAI_API_KEY",
    "OPENROUTER_API_KEY",
    "TOGETHER_API_KEY",
    "FIREWORKS_API_KEY",
    "CEREBRAS_API_KEY",
    "MOONSHOT_API_KEY",
    "HYPERBOLIC_API_KEY",
    "HF_TOKEN",
    "NVIDIA_API_KEY",
    "SAMBANOVA_API_KEY",
    "COHERE_API_KEY",
    "CO_API_KEY",
    "VLLM_API_KEY",
    "OPENAI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_VERSION",
    "OPENAI_API_VERSION",
];

/// Holds the env lock, starts from a clean slate and puts every variable
/// back as it was on drop.
struct EnvGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let saved = ALL_VARS.iter().map(|&v| (v, std::env::var_os(v))).collect();
        let guard = Self { saved, _lock: lock };
        for var in ALL_VARS {
            guard.remove(var);
        }
        guard
    }

    #[allow(clippy::unused_self, reason = "ties the change to the held lock")]
    fn set(&self, name: &str, value: &str) {
        // SAFETY: ENV_LOCK serialises every env change in this test binary.
        unsafe { std::env::set_var(name, value) };
    }

    #[allow(clippy::unused_self, reason = "ties the change to the held lock")]
    fn remove(&self, name: &str) {
        // SAFETY: as above.
        unsafe { std::env::remove_var(name) };
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            // SAFETY: the lock is still held; it is released after this.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// `from_env` must read `var` and send it as a bearer token to
/// `{mock}/v1/chat/completions`, and fail naming `var` when it is unset.
fn check_from_env<P: Preset>(var: &str) {
    let env = EnvGuard::new();
    let err = compat::Client::<P>::from_env().unwrap_err();
    assert!(err.message().contains(var), "{var}: {}", err.message());

    // A blank value counts as unset.
    env.set(var, "  ");
    assert!(compat::Client::<P>::from_env().is_err(), "{var}");

    let secret = format!("secret-for-{var}");
    env.set(var, &secret);
    let server = MockServer::start([MockResponse::json(200, CHAT)]).unwrap();
    let client = compat::Client::<P>::from_env()
        .unwrap()
        .with_base_url(format!("{}/v1", server.base_url()))
        .configure(|llm| llm.http_client(http()));
    assert_eq!(client.provider(), P::PROVIDER);
    assert!(!format!("{client:?}").contains(&secret), "{var}");
    let out = runtime()
        .block_on(
            client
                .completion_model("m")
                .generate(&[Message::human("hi")]),
        )
        .unwrap();
    assert_eq!(out.generation, "hi");
    let req = &server.finish().unwrap()[0];
    assert_eq!(req.path, "/v1/chat/completions", "{var}");
    let bearer = format!("Bearer {secret}");
    assert_eq!(req.header("authorization"), Some(bearer.as_str()), "{var}");
    assert_eq!(req.json().unwrap()["model"], "m");
}

#[test]
fn from_env_reads_each_providers_key() {
    check_from_env::<groq::Groq>("GROQ_API_KEY");
    check_from_env::<mistral::Mistral>("MISTRAL_API_KEY");
    check_from_env::<deepseek::DeepSeek>("DEEPSEEK_API_KEY");
    check_from_env::<xai::Xai>("XAI_API_KEY");
    check_from_env::<openrouter::OpenRouter>("OPENROUTER_API_KEY");
    check_from_env::<together::Together>("TOGETHER_API_KEY");
    check_from_env::<fireworks::Fireworks>("FIREWORKS_API_KEY");
    check_from_env::<cerebras::Cerebras>("CEREBRAS_API_KEY");
    check_from_env::<moonshot::Moonshot>("MOONSHOT_API_KEY");
    check_from_env::<hyperbolic::Hyperbolic>("HYPERBOLIC_API_KEY");
    check_from_env::<huggingface::HuggingFace>("HF_TOKEN");
    check_from_env::<nvidia::NvidiaNim>("NVIDIA_API_KEY");
    check_from_env::<sambanova::SambaNova>("SAMBANOVA_API_KEY");
    check_from_env::<cohere::Cohere>("COHERE_API_KEY");
}

#[test]
fn from_env_ignores_other_providers_keys() {
    let env = EnvGuard::new();
    env.set("OPENAI_API_KEY", "openai");
    env.set("GROQ_API_KEY", "groq");
    assert!(xai::Client::from_env().is_err());
    assert!(mistral::Client::from_env().is_err());
}

#[test]
fn cohere_falls_back_to_co_api_key() {
    let env = EnvGuard::new();
    env.set("CO_API_KEY", "co-key");
    let server = MockServer::start([MockResponse::json(200, CHAT)]).unwrap();
    let client = cohere::Client::from_env()
        .unwrap()
        .with_base_url(server.base_url())
        .configure(|llm| llm.http_client(http()));
    runtime()
        .block_on(
            client
                .completion_model("command")
                .generate(&[Message::human("hi")]),
        )
        .unwrap();
    let req = &server.finish().unwrap()[0];
    assert_eq!(req.header("authorization"), Some("Bearer co-key"));

    // COHERE_API_KEY wins when both are set.
    env.set("COHERE_API_KEY", "cohere-key");
    let server = MockServer::start([MockResponse::json(200, CHAT)]).unwrap();
    let client = cohere::Client::from_env()
        .unwrap()
        .with_base_url(server.base_url())
        .configure(|llm| llm.http_client(http()));
    runtime()
        .block_on(
            client
                .completion_model("command")
                .generate(&[Message::human("hi")]),
        )
        .unwrap();
    let req = &server.finish().unwrap()[0];
    assert_eq!(req.header("authorization"), Some("Bearer cohere-key"));
}

#[test]
fn local_servers_need_no_key() {
    let env = EnvGuard::new();
    let server = MockServer::start([
        MockResponse::json(200, CHAT),
        MockResponse::json(200, CHAT),
        MockResponse::json(200, CHAT),
    ])
    .unwrap();
    let base = format!("{}/v1", server.base_url());
    let lm = lmstudio::Client::from_env()
        .unwrap()
        .with_base_url(&base)
        .configure(|llm| llm.http_client(http()));
    let vl = vllm::Client::from_env()
        .unwrap()
        .with_base_url(&base)
        .configure(|llm| llm.http_client(http()));
    env.set("VLLM_API_KEY", "vllm-key");
    let vl_keyed = vllm::Client::from_env()
        .unwrap()
        .with_base_url(&base)
        .configure(|llm| llm.http_client(http()));
    let rt = runtime();
    let models = [
        lm.completion_model("m"),
        vl.completion_model("m"),
        vl_keyed.completion_model("m"),
    ];
    for model in models {
        rt.block_on(model.generate(&[Message::human("hi")]))
            .unwrap();
    }
    let reqs = server.finish().unwrap();
    assert_eq!(reqs[0].header("authorization"), None);
    assert_eq!(reqs[1].header("authorization"), None);
    assert_eq!(reqs[2].header("authorization"), Some("Bearer vllm-key"));
}

#[test]
fn default_base_urls_come_from_the_presets() {
    let cases = [
        (
            groq::Client::new("k").completion_model("m"),
            "https://api.groq.com/openai/v1",
        ),
        (
            xai::Client::new("k").completion_model("m"),
            "https://api.x.ai/v1",
        ),
        (
            fireworks::Client::new("k").completion_model("m"),
            "https://api.fireworks.ai/inference/v1",
        ),
        (
            huggingface::Client::new("k").completion_model("m"),
            "https://router.huggingface.co/v1",
        ),
        (
            cohere::Client::new("k").completion_model("m"),
            "https://api.cohere.ai/compatibility/v1",
        ),
        (
            lmstudio::Client::new("").completion_model("m"),
            "http://localhost:1234/v1",
        ),
    ];
    for (model, url) in cases {
        assert_eq!(model.base_url_str(), url);
    }
}

/// Embedding models share the client's key and base URL.
fn check_embeddings<P: rune_chain::compat::EmbeddingPreset>() {
    let server = MockServer::start([MockResponse::json(200, EMBED)]).unwrap();
    let client =
        compat::Client::<P>::new("emb-key").with_base_url(format!("{}/v1", server.base_url()));
    let embedder = client.embedding_model("embed-model").http_client(http());
    let vector = runtime().block_on(embedder.embed("hello")).unwrap();
    assert_eq!(vector, [0.5, 0.25]);
    let req = &server.finish().unwrap()[0];
    assert_eq!(req.path, "/v1/embeddings");
    assert_eq!(req.header("authorization"), Some("Bearer emb-key"));
    assert_eq!(req.json().unwrap()["model"], "embed-model");
}

#[test]
fn embedding_providers_hand_out_embedders() {
    check_embeddings::<mistral::Mistral>();
    check_embeddings::<fireworks::Fireworks>();
    check_embeddings::<cohere::Cohere>();
    check_embeddings::<vllm::Vllm>();
    check_embeddings::<lmstudio::LmStudio>();
}

#[test]
fn azure_from_env_reads_endpoint_key_and_version() {
    let env = EnvGuard::new();
    let err = azure::Client::from_env().unwrap_err();
    assert!(err.message().contains("AZURE_OPENAI_ENDPOINT"));

    let server = MockServer::start([MockResponse::json(200, CHAT)]).unwrap();
    env.set("AZURE_OPENAI_ENDPOINT", server.base_url());
    let err = azure::Client::from_env().unwrap_err();
    assert!(err.message().contains("AZURE_OPENAI_API_KEY"));

    env.set("AZURE_OPENAI_API_KEY", "az-key");
    env.set("OPENAI_API_VERSION", "2024-06-01");
    let model = azure::Client::from_env().unwrap().completion_model("dep");
    assert!(
        model
            .chat_url()
            .unwrap()
            .as_str()
            .ends_with("api-version=2024-06-01")
    );

    // The Azure-specific variable wins over the generic one.
    env.set("AZURE_OPENAI_API_VERSION", "2024-10-21");
    let client = azure::Client::from_env()
        .unwrap()
        .configure(|llm| llm.http_client(http()));
    runtime()
        .block_on(
            client
                .completion_model("prod-4o")
                .generate(&[Message::human("hi")]),
        )
        .unwrap();
    let req = &server.finish().unwrap()[0];
    assert_eq!(
        req.path,
        "/openai/deployments/prod-4o/chat/completions?api-version=2024-10-21"
    );
    assert_eq!(req.header("api-key"), Some("az-key"));
    assert_eq!(req.header("authorization"), None);
}
