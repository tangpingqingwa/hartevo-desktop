//! Read-only growth signal connector adapters.
//!
//! The crate owns only the provider-specific DataForSEO Labs request, response,
//! transport, cursor, cost, freshness, and Mission-consumer types. Generic
//! auth, fencing, registration metadata, and worker lifecycle come from
//! `hartevo-connector-sdk`; this crate does not create a second connector API.

mod dataforseo_labs;
mod env;
mod mission;

pub use dataforseo_labs::*;
pub use env::*;
pub use mission::*;

pub const DATAFORSEO_LABS_READ_CONTRACT_JSON: &str =
    include_str!("../../../contracts/providers/dataforseo-labs-read.v1.json");
pub const DATAFORSEO_LABS_READ_CONTRACT_VERSION: &str = "dataforseo-labs-read/v1";
pub const DATAFORSEO_PROVIDER_ID: &str = "dataforseo";
pub const DATAFORSEO_LABS_ADAPTER_ID: &str = "dataforseo.labs";
pub const DATAFORSEO_LABS_ADAPTER_VERSION: u32 = 1;
pub const DATAFORSEO_LABS_READ_CAPABILITY: &str = "research.discover";
pub const DATAFORSEO_API_VERSION: &str = "v3";
pub const DATAFORSEO_API_BASE_URL: &str = "https://api.dataforseo.com/";
pub const DATAFORSEO_LABS_KEYWORDS_FOR_SITE_PATH: &str =
    "/v3/dataforseo_labs/google/keywords_for_site/live";
pub const DATAFORSEO_USER_DATA_PATH: &str = "/v3/appendix/user_data";
pub const DATAFORSEO_LABS_STATUS_PATH: &str = "/v3/dataforseo_labs/status";
