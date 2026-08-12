use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;

use crate::{ContextAssemblyError, ContextTokenizer, ContextTokenizerProfile};

const MAX_TOKENIZER_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;
const CONSERVATIVE_BYTE_BUDGET_SPEC: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/context/conservative-byte-budget-v1.json"
));

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnedTokenizerSpec {
    pub provider: String,
    pub model: String,
    pub model_revision: String,
    pub expected_artifact_digest: String,
    pub add_special_tokens: bool,
    pub request_overhead_tokens: u64,
    pub max_input_bytes: u64,
}

impl PinnedTokenizerSpec {
    pub fn profile(&self) -> Result<ContextTokenizerProfile, ContextAssemblyError> {
        ContextTokenizerProfile::new(
            self.provider.clone(),
            self.model.clone(),
            self.model_revision.clone(),
            self.expected_artifact_digest.clone(),
            self.add_special_tokens,
            self.request_overhead_tokens,
            self.max_input_bytes,
        )
    }
}

impl fmt::Debug for PinnedTokenizerSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedTokenizerSpec")
            .field("provider_digest", &digest(self.provider.as_bytes()))
            .field("model_digest", &digest(self.model.as_bytes()))
            .field(
                "model_revision_digest",
                &digest(self.model_revision.as_bytes()),
            )
            .field("expected_artifact_digest", &self.expected_artifact_digest)
            .field("add_special_tokens", &self.add_special_tokens)
            .field("request_overhead_tokens", &self.request_overhead_tokens)
            .field("max_input_bytes", &self.max_input_bytes)
            .finish()
    }
}

pub struct PinnedModelTokenizer {
    profile: ContextTokenizerProfile,
    tokenizer: Tokenizer,
}

impl PinnedModelTokenizer {
    pub fn from_json_bytes(
        spec: &PinnedTokenizerSpec,
        tokenizer_json: &[u8],
    ) -> Result<Self, ContextAssemblyError> {
        let profile = spec.profile()?;
        if tokenizer_json.is_empty()
            || tokenizer_json.len() > MAX_TOKENIZER_ARTIFACT_BYTES
            || digest(tokenizer_json) != profile.artifact_digest
        {
            return Err(ContextAssemblyError::InvalidTokenizerProfile);
        }
        let tokenizer = Tokenizer::from_bytes(tokenizer_json)
            .map_err(|_| ContextAssemblyError::InvalidTokenizerProfile)?;
        Ok(Self { profile, tokenizer })
    }

    pub fn tokenizer_profile(&self) -> &ContextTokenizerProfile {
        &self.profile
    }
}

impl ContextTokenizer for PinnedModelTokenizer {
    fn profile(&self) -> Result<ContextTokenizerProfile, ContextAssemblyError> {
        Ok(self.profile.clone())
    }

    fn count_tokens(&self, text: &str) -> Result<u64, ContextAssemblyError> {
        let byte_count =
            u64::try_from(text.len()).map_err(|_| ContextAssemblyError::TokenizerFailure)?;
        if text.is_empty() || byte_count > self.profile.max_input_bytes {
            return Err(ContextAssemblyError::TokenizerFailure);
        }
        let encoding = self
            .tokenizer
            .encode(text, self.profile.add_special_tokens)
            .map_err(|_| ContextAssemblyError::TokenizerFailure)?;
        let content_tokens = u64::try_from(encoding.get_ids().len())
            .map_err(|_| ContextAssemblyError::TokenizerFailure)?;
        if content_tokens == 0 {
            return Err(ContextAssemblyError::TokenizerFailure);
        }
        Ok(content_tokens)
    }
}

impl fmt::Debug for PinnedModelTokenizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedModelTokenizer")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// A deliberately conservative development fallback used before Hartevo has
/// provider model-revision proof and an exact tokenizer artifact.
///
/// Counting one unit per UTF-8 byte overestimates ordinary BPE token counts,
/// so it can safely narrow a Context budget. It is not an exact tokenizer and
/// its profile revision makes that limitation machine-visible. Release gates
/// must continue to treat this profile as non-production evidence.
pub struct ConservativeByteBudgetTokenizer {
    profile: ContextTokenizerProfile,
}

impl ConservativeByteBudgetTokenizer {
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        request_overhead_tokens: u64,
        max_input_bytes: u64,
    ) -> Result<Self, ContextAssemblyError> {
        let profile = ContextTokenizerProfile::new(
            provider,
            model,
            "runtime-reported-model-unverified",
            digest(CONSERVATIVE_BYTE_BUDGET_SPEC),
            false,
            request_overhead_tokens,
            max_input_bytes,
        )?;
        Ok(Self { profile })
    }

    pub fn tokenizer_profile(&self) -> &ContextTokenizerProfile {
        &self.profile
    }

    pub fn contract_bytes() -> &'static [u8] {
        CONSERVATIVE_BYTE_BUDGET_SPEC
    }
}

impl ContextTokenizer for ConservativeByteBudgetTokenizer {
    fn profile(&self) -> Result<ContextTokenizerProfile, ContextAssemblyError> {
        Ok(self.profile.clone())
    }

    fn count_tokens(&self, text: &str) -> Result<u64, ContextAssemblyError> {
        let byte_count =
            u64::try_from(text.len()).map_err(|_| ContextAssemblyError::TokenizerFailure)?;
        if byte_count == 0 || byte_count > self.profile.max_input_bytes {
            return Err(ContextAssemblyError::TokenizerFailure);
        }
        Ok(byte_count)
    }
}

impl fmt::Debug for ConservativeByteBudgetTokenizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConservativeByteBudgetTokenizer")
            .field("profile", &self.profile)
            .field("exact_model_tokenizer", &false)
            .finish()
    }
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORD_LEVEL_TOKENIZER: &str = r#"{
      "version":"1.0",
      "truncation":null,
      "padding":null,
      "added_tokens":[],
      "normalizer":null,
      "pre_tokenizer":{"type":"WhitespaceSplit"},
      "post_processor":null,
      "decoder":null,
      "model":{
        "type":"WordLevel",
        "vocab":{"<unk>":0,"hello":1,"world":2,"日本":3},
        "unk_token":"<unk>"
      }
    }"#;

    fn spec(digest: String) -> PinnedTokenizerSpec {
        PinnedTokenizerSpec {
            provider: "fixture-provider".into(),
            model: "fixture-model".into(),
            model_revision: "revision-2026-08-11".into(),
            expected_artifact_digest: digest,
            add_special_tokens: false,
            request_overhead_tokens: 3,
            max_input_bytes: 1_024,
        }
    }

    #[test]
    fn pinned_artifact_counts_exact_tokens_and_request_overhead() {
        let bytes = WORD_LEVEL_TOKENIZER.as_bytes();
        let tokenizer = PinnedModelTokenizer::from_json_bytes(&spec(digest(bytes)), bytes)
            .expect("pinned tokenizer");
        assert_eq!(
            tokenizer
                .count_tokens("hello world hello")
                .expect("exact token count"),
            3
        );
        assert_eq!(
            tokenizer
                .count_tokens("日本 world")
                .expect("unicode token count"),
            2
        );
        assert_eq!(tokenizer.tokenizer_profile().request_overhead_tokens, 3);
        assert_eq!(
            tokenizer
                .tokenizer_profile()
                .digest()
                .expect("profile digest"),
            tokenizer
                .profile()
                .expect("profile")
                .digest()
                .expect("digest")
        );
        let debug = format!("{tokenizer:?}");
        assert!(!debug.contains("fixture-model"));
        assert!(!debug.contains(WORD_LEVEL_TOKENIZER));
    }

    #[test]
    fn artifact_swap_malformed_json_and_oversized_input_fail_closed() {
        let bytes = WORD_LEVEL_TOKENIZER.as_bytes();
        assert!(matches!(
            PinnedModelTokenizer::from_json_bytes(&spec("0".repeat(64)), bytes),
            Err(ContextAssemblyError::InvalidTokenizerProfile)
        ));
        let malformed = b"{not-a-tokenizer}";
        assert!(matches!(
            PinnedModelTokenizer::from_json_bytes(&spec(digest(malformed)), malformed),
            Err(ContextAssemblyError::InvalidTokenizerProfile)
        ));
        let mut bounded_spec = spec(digest(bytes));
        bounded_spec.max_input_bytes = 4;
        let tokenizer =
            PinnedModelTokenizer::from_json_bytes(&bounded_spec, bytes).expect("bounded tokenizer");
        assert!(matches!(
            tokenizer.count_tokens("hello"),
            Err(ContextAssemblyError::TokenizerFailure)
        ));
    }

    #[test]
    fn profile_digest_changes_with_model_or_chat_overhead() {
        let bytes = WORD_LEVEL_TOKENIZER.as_bytes();
        let first = spec(digest(bytes)).profile().expect("first profile");
        let mut changed = spec(digest(bytes));
        changed.request_overhead_tokens += 1;
        let changed = changed.profile().expect("changed profile");
        assert_ne!(
            first.digest().expect("first digest"),
            changed.digest().expect("changed digest")
        );
        assert!(
            ContextTokenizerProfile::new(
                " provider ",
                "model",
                "revision",
                digest(bytes),
                false,
                0,
                1_024,
            )
            .is_err()
        );
    }

    #[test]
    fn conservative_byte_budget_is_bounded_redacted_and_never_claims_exactness() {
        let tokenizer =
            ConservativeByteBudgetTokenizer::new("openai", "gpt-5.6-sol", 2_048, 16_384)
                .expect("conservative profile");
        assert_eq!(
            tokenizer.count_tokens("hello 日本").expect("byte budget"),
            u64::try_from("hello 日本".len()).expect("length")
        );
        assert_eq!(
            tokenizer.tokenizer_profile().model_revision,
            "runtime-reported-model-unverified"
        );
        assert_eq!(
            tokenizer.tokenizer_profile().artifact_digest,
            digest(ConservativeByteBudgetTokenizer::contract_bytes())
        );
        let contract: serde_json::Value =
            serde_json::from_slice(ConservativeByteBudgetTokenizer::contract_bytes())
                .expect("machine-readable contract");
        assert_eq!(contract["exactModelTokenizer"], false);
        let debug = format!("{tokenizer:?}");
        assert!(!debug.contains("gpt-5.6-sol"));
        assert!(!debug.contains("openai"));
        assert!(matches!(
            tokenizer.count_tokens(""),
            Err(ContextAssemblyError::TokenizerFailure)
        ));
    }
}
