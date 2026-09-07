//! Native OpenAI-compatible and Grok chat completions for Cordis.
//!
//! Shares the bounded HTTPS/SSE transport, tool history, cancellation, and
//! redaction rules with the DeepSeek adapter. Provider identity stays exact;
//! compatible traffic is never recorded as a DeepSeek call. Connection limits
//! are supplied by the caller, not inferred from a model name or alias.

use hartevo_cordis::{
    LlmAdapter, LlmAdapterStream, LlmError, LlmGenerateRequest, LlmResolvedModel, SessionLlmFailure,
};

use crate::llm_deepseek::{
    DeepSeekAdapter, DeepSeekConnectionResolver, DeepSeekCredentialResolver, DeepSeekTransport,
    EnvironmentCredentialResolver, UreqDeepSeekTransport,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatCompletionsProvider {
    OpenAi,
    Grok,
}

impl ChatCompletionsProvider {
    pub const fn id(self) -> &'static str {
        match self {
            Self::OpenAi => "openai-compatible",
            Self::Grok => "grok-compatible",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "openai-compatible" => Some(Self::OpenAi),
            "grok-compatible" => Some(Self::Grok),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenAiCompatibleAdapter {
    provider: ChatCompletionsProvider,
    inner: DeepSeekAdapter,
}

impl OpenAiCompatibleAdapter {
    pub fn new<C, R, T>(
        provider: ChatCompletionsProvider,
        connection: C,
        credentials: R,
        transport: T,
    ) -> Self
    where
        C: DeepSeekConnectionResolver,
        R: DeepSeekCredentialResolver,
        T: DeepSeekTransport,
    {
        Self {
            provider,
            inner: DeepSeekAdapter::new(connection, credentials, transport)
                .with_compatible_provider(provider),
        }
    }

    pub fn production<C>(provider: ChatCompletionsProvider, connection: C) -> Self
    where
        C: DeepSeekConnectionResolver,
    {
        Self::new(
            provider,
            connection,
            EnvironmentCredentialResolver,
            UreqDeepSeekTransport,
        )
    }

    pub const fn provider(&self) -> ChatCompletionsProvider {
        self.provider
    }
}

impl LlmAdapter for OpenAiCompatibleAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        self.inner.prepare_model(provider, model)
    }

    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        self.inner.stream(request)
    }
}
