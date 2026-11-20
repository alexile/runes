//! The client behind the OpenAI-compatible provider modules
//! ([`groq`](crate::groq), [`mistral`](crate::mistral), [`xai`](crate::xai),
//! …). Each module is a [`Preset`] marker plus `type Client =
//! compat::Client<Marker>`, so they all share this one implementation.

use std::fmt;
use std::marker::PhantomData;

use rune_chain_core::LlmError;
use rune_chain_embed::OpenAiEmbedder;
use rune_chain_openai::{OpenAi, Provider};

use crate::{CompletionClient, EmbeddingsClient};

/// An OpenAI-compatible provider: which [`Provider`] preset to start from
/// and where its key lives.
pub trait Preset: 'static {
    /// The `rune-chain-openai` preset (base URL and wire quirks).
    const PROVIDER: Provider;
    /// Environment variables checked by [`Client::from_env`], in order; the
    /// first one set to a non-empty value wins.
    const API_KEY_ENVS: &'static [&'static str];
}

/// A [`Preset`] whose server has an OpenAI-style `/embeddings` endpoint.
pub trait EmbeddingPreset: Preset {}

/// Client for an OpenAI-compatible provider: hands out chat models
/// ([`OpenAi`]) and, where the provider has embeddings, embedding models
/// ([`OpenAiEmbedder`]) that share one key and base URL.
///
/// Use it through a provider module, e.g. `rune_chain::groq::Client`.
pub struct Client<P> {
    inner: crate::openai::Client,
    preset: PhantomData<fn() -> P>,
}

impl<P> Clone for Client<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            preset: PhantomData,
        }
    }
}

impl<P> fmt::Debug for Client<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<P: Preset> Client<P> {
    /// A client for the provider's default endpoint with `api_key`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            inner: crate::openai::Client::for_provider(P::PROVIDER, api_key),
            preset: PhantomData,
        }
    }

    /// A client from the provider's key variable ([`Preset::API_KEY_ENVS`]).
    /// Local servers (vLLM, LM Studio) run without a key when none is set.
    ///
    /// # Errors
    ///
    /// When no key variable is set and the provider needs a key.
    pub fn from_env() -> Result<Self, LlmError> {
        let key = P::API_KEY_ENVS
            .iter()
            .find_map(|var| std::env::var(var).ok().filter(|k| !k.trim().is_empty()));
        match key {
            Some(key) => Ok(Self::new(key)),
            None if P::PROVIDER.key_optional() || P::API_KEY_ENVS.is_empty() => {
                Ok(Self::new(String::new()))
            }
            None => Err(LlmError::other(format!(
                "{} environment variable not set",
                P::API_KEY_ENVS.join(" or ")
            ))),
        }
    }

    /// Point the client at another base URL (`…/v1`), e.g. a self-hosted
    /// server or a proxy. The provider's quirks stay.
    #[must_use]
    pub fn with_base_url(self, base_url: impl Into<String>) -> Self {
        let base_url = base_url.into();
        self.configure(|llm| llm.base_url(base_url))
    }

    /// Adjust the underlying [`OpenAi`] template (timeouts, headers,
    /// quirks). Every model handed out afterwards starts from it.
    #[must_use]
    pub fn configure(mut self, f: impl FnOnce(OpenAi) -> OpenAi) -> Self {
        self.inner = self.inner.configure(f);
        self
    }

    /// The provider preset this client uses.
    #[must_use]
    pub const fn provider(&self) -> Provider {
        P::PROVIDER
    }
}

impl<P: Preset> CompletionClient for Client<P> {
    type Model = OpenAi;

    fn completion_model(&self, name: &str) -> OpenAi {
        self.inner.completion_model(name)
    }
}

impl<P: EmbeddingPreset> EmbeddingsClient for Client<P> {
    type Embedder = OpenAiEmbedder;

    fn embedding_model(&self, name: &str) -> OpenAiEmbedder {
        self.inner.embedding_model(name)
    }
}

/// Declare one provider module: a marker type, its [`Preset`] impl and a
/// `Client` alias, with a doc example.
macro_rules! preset_module {
    (
        $(#[$doc:meta])*
        $module:ident, $marker:ident, $feature:literal, $provider:ident,
        keys: [$($key:literal),*],
        embeddings: $emb:tt,
        model: $model:literal $(,)?
    ) => {
        $(#[$doc])*
        ///
        /// ```rust
        #[doc = concat!("use rune_chain::", stringify!($module), ";")]
        /// use rune_chain::prelude::*;
        ///
        #[doc = concat!("let client = ", stringify!($module), "::Client::new(\"key\");")]
        #[doc = concat!("let model = client.completion_model(\"", $model, "\");")]
        #[doc = concat!("assert_eq!(model.model_id(), \"", $model, "\");")]
        #[doc = concat!("assert_eq!(model.provider(), ", stringify!($module), "::Provider::", stringify!($provider), ");")]
        /// ```
        #[cfg(feature = $feature)]
        pub mod $module {
            pub use rune_chain_openai::{OpenAi, Provider, Quirks};

            /// Environment variables read by [`Client::from_env`], in order.
            pub const API_KEY_ENVS: &[&str] = &[$($key),*];

            #[doc = concat!("The [`Preset`](crate::compat::Preset) for `Provider::", stringify!($provider), "`.")]
            #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
            pub struct $marker;

            impl crate::compat::Preset for $marker {
                const PROVIDER: Provider = Provider::$provider;
                const API_KEY_ENVS: &'static [&'static str] = API_KEY_ENVS;
            }

            preset_module!(@embeddings $emb $marker);

            /// Client for this provider; see [`compat::Client`](crate::compat::Client).
            pub type Client = crate::compat::Client<$marker>;
        }
    };
    (@embeddings true $marker:ident) => {
        impl crate::compat::EmbeddingPreset for $marker {}
    };
    (@embeddings false $marker:ident) => {};
}
