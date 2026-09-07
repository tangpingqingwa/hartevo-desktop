//! Bounded, one-shot HTTPS media transport. Never returns provider bodies in errors.

use std::{io::Cursor, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hartevo_domain_kernel::media_generation::{
    MAX_MEDIA_BYTES, MediaAssetMetadata, MediaGeneration, MediaGenerationRequest, MediaKind,
    MediaProvider, valid_token,
};
use image::{GenericImageView, ImageFormat, ImageReader, Limits};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct MediaConnection {
    api_base: Url,
    key_env: String,
}

impl std::fmt::Debug for MediaConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MediaConnection([REDACTED])")
    }
}

impl MediaConnection {
    pub fn new(base: &str, key_env: &str) -> Result<Self, MediaProviderError> {
        let base = base.trim_end_matches('/');
        let base = if base.ends_with("/v1") {
            base.to_owned()
        } else {
            format!("{base}/v1")
        };
        let api_base = Url::parse(&base).map_err(|_| error("MEDIA_CONFIG_INVALID"))?;
        if api_base.scheme() != "https"
            || api_base.host_str().is_none()
            || !api_base.username().is_empty()
            || api_base.password().is_some()
            || api_base.query().is_some()
            || api_base.fragment().is_some()
            || key_env.is_empty()
            || key_env.len() > 128
            || !key_env.starts_with(|c: char| c.is_ascii_uppercase() || c == '_')
            || !key_env
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(error("MEDIA_CONFIG_INVALID"));
        }
        Ok(Self {
            api_base,
            key_env: key_env.into(),
        })
    }

    pub fn digest(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(format!("{}\n{}", self.api_base, self.key_env).as_bytes())
        )
    }

    pub fn is_configured(&self) -> bool {
        std::env::var(&self.key_env).is_ok_and(|value| !value.trim().is_empty())
    }

    fn credential(&self) -> Result<Zeroizing<String>, MediaProviderError> {
        let key = Zeroizing::new(
            std::env::var(&self.key_env).map_err(|_| error("MEDIA_CREDENTIAL_MISSING"))?,
        );
        if key.trim().is_empty() {
            return Err(error("MEDIA_CREDENTIAL_MISSING"));
        }
        Ok(key)
    }
}

pub enum MediaProviderOutput {
    Pending(String),
    Asset {
        metadata: MediaAssetMetadata,
        bytes: Vec<u8>,
    },
    Waiting,
    Failed(&'static str),
}

impl std::fmt::Debug for MediaProviderOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending(_) => "Pending",
            Self::Asset { .. } => "Asset",
            Self::Waiting => "Waiting",
            Self::Failed(_) => "Failed",
        })
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("{code}")]
pub struct MediaProviderError {
    pub code: &'static str,
}

fn error(code: &'static str) -> MediaProviderError {
    MediaProviderError { code }
}

pub trait MediaTransport: Send + Sync {
    fn submit(
        &self,
        request: &MediaGenerationRequest,
    ) -> Result<MediaProviderOutput, MediaProviderError>;
    fn poll(&self, job: &MediaGeneration) -> Result<MediaProviderOutput, MediaProviderError>;
}

#[derive(Debug)]
pub struct NativeMediaTransport {
    pub connection: MediaConnection,
}

impl NativeMediaTransport {
    fn agent(timeout: u64) -> ureq::Agent {
        ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(true)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(timeout)))
            .user_agent("hartevo-native-media/1")
            .build()
            .into()
    }

    fn call(&self, route: &str, payload: Option<Value>) -> Result<Value, MediaProviderError> {
        let credential = self.connection.credential()?;
        let authorization = Zeroizing::new(format!("Bearer {}", credential.as_str()));
        let endpoint = format!("{}{route}", self.connection.api_base);
        let agent = Self::agent(if payload.is_some() { 150 } else { 30 });
        let response = if let Some(payload) = payload {
            agent
                .post(&endpoint)
                .header("Authorization", authorization.as_str())
                .send_json(payload)
        } else {
            agent
                .get(&endpoint)
                .header("Authorization", authorization.as_str())
                .call()
        };
        let mut response = response.map_err(|_| error("MEDIA_TRANSPORT_UNCERTAIN"))?;
        if !response.status().is_success() {
            return Err(error("MEDIA_PROVIDER_HTTP_ERROR"));
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit((MAX_MEDIA_BYTES * 2) as u64)
            .read_to_vec()
            .map_err(|_| error("MEDIA_RESPONSE_INVALID"))?;
        serde_json::from_slice(&bytes).map_err(|_| error("MEDIA_RESPONSE_INVALID"))
    }

    fn asset(
        &self,
        value: &Value,
        kind: MediaKind,
    ) -> Result<MediaProviderOutput, MediaProviderError> {
        let bytes = if let Some(encoded) = value["b64_json"].as_str() {
            if encoded.len() > MAX_MEDIA_BYTES * 2 {
                return Err(error("MEDIA_ASSET_TOO_LARGE"));
            }
            STANDARD
                .decode(encoded)
                .map_err(|_| error("MEDIA_ASSET_INVALID"))?
        } else {
            self.download(value["url"].as_str().ok_or(error("MEDIA_ASSET_MISSING"))?)?
        };
        let metadata = inspect_media(&bytes, kind)?;
        Ok(MediaProviderOutput::Asset { metadata, bytes })
    }

    fn asset_url(&self, value: &str) -> Result<Url, MediaProviderError> {
        let url = self
            .connection
            .api_base
            .join(value)
            .map_err(|_| error("MEDIA_ASSET_URL_INVALID"))?;
        // Only the explicitly configured origin is trusted. Redirects and other
        // origins are refused; private gateway/VPN addresses remain usable.
        if url.scheme() != "https"
            || url.origin() != self.connection.api_base.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(error("MEDIA_ASSET_ORIGIN_NOT_ALLOWED"));
        }
        Ok(url)
    }

    fn download(&self, value: &str) -> Result<Vec<u8>, MediaProviderError> {
        let url = self.asset_url(value)?;
        let authorization =
            Zeroizing::new(format!("Bearer {}", self.connection.credential()?.as_str()));
        let mut response = Self::agent(30)
            .get(url.as_str())
            .header("Authorization", authorization.as_str())
            .call()
            .map_err(|_| error("MEDIA_ASSET_DOWNLOAD_FAILED"))?;
        if !response.status().is_success() {
            return Err(error("MEDIA_ASSET_DOWNLOAD_FAILED"));
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_MEDIA_BYTES as u64)
            .read_to_vec()
            .map_err(|_| error("MEDIA_ASSET_DOWNLOAD_FAILED"))
    }
}

impl MediaTransport for NativeMediaTransport {
    fn submit(
        &self,
        request: &MediaGenerationRequest,
    ) -> Result<MediaProviderOutput, MediaProviderError> {
        request
            .validate()
            .map_err(|_| error("MEDIA_CONFIG_INVALID"))?;
        if request.endpoint_digest != self.connection.digest() {
            return Err(error("MEDIA_CONNECTION_CHANGED"));
        }
        let mut payload = json!({"model":request.model,"prompt":request.prompt});
        if request.kind == MediaKind::Video {
            payload["duration"] = json!(3);
            payload["aspect_ratio"] = json!("1:1");
            payload["resolution"] = json!("480p");
            let value = self.call("/videos/generations", Some(payload))?;
            let id = value["request_id"]
                .as_str()
                .filter(|id| valid_token(id))
                .ok_or(error("MEDIA_JOB_ID_INVALID"))?;
            return Ok(MediaProviderOutput::Pending(id.into()));
        }
        payload["n"] = json!(1);
        match request.provider {
            MediaProvider::OpenAi => {
                payload["size"] = json!("1024x1024");
                payload["quality"] = json!("low");
            }
            MediaProvider::Grok => {
                payload["aspect_ratio"] = json!("1:1");
                payload["response_format"] = json!("b64_json");
            }
        }
        let value = self.call("/images/generations", Some(payload))?;
        let items = value["data"]
            .as_array()
            .filter(|items| items.len() == 1)
            .ok_or(error("MEDIA_ASSET_MISSING"))?;
        self.asset(&items[0], MediaKind::Image)
    }

    fn poll(&self, job: &MediaGeneration) -> Result<MediaProviderOutput, MediaProviderError> {
        if job.request.endpoint_digest != self.connection.digest() {
            return Err(error("MEDIA_CONNECTION_CHANGED"));
        }
        let id = job
            .provider_request_id
            .as_deref()
            .filter(|id| valid_token(id))
            .ok_or(error("MEDIA_JOB_ID_INVALID"))?;
        let value = self.call(&format!("/videos/{id}"), None)?;
        match value["status"].as_str() {
            Some("done") => self.asset(&value["video"], MediaKind::Video),
            Some("pending" | "processing" | "queued" | "running") => {
                Ok(MediaProviderOutput::Waiting)
            }
            Some("failed" | "expired") => Ok(MediaProviderOutput::Failed(
                "MEDIA_PROVIDER_GENERATION_FAILED",
            )),
            _ => Err(error("MEDIA_JOB_STATE_INVALID")),
        }
    }
}

pub fn inspect_media(
    bytes: &[u8],
    kind: MediaKind,
) -> Result<MediaAssetMetadata, MediaProviderError> {
    if bytes.is_empty() || bytes.len() > MAX_MEDIA_BYTES {
        return Err(error("MEDIA_ASSET_TOO_LARGE"));
    }
    let (media_type, width, height, duration_millis) = match kind {
        MediaKind::Image => {
            let format = image::guess_format(bytes).map_err(|_| error("MEDIA_IMAGE_INVALID"))?;
            let media_type = match format {
                ImageFormat::Png => "image/png",
                ImageFormat::Jpeg => "image/jpeg",
                _ => return Err(error("MEDIA_IMAGE_FORMAT_UNSUPPORTED")),
            };
            let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
            let mut limits = Limits::default();
            limits.max_image_width = Some(4096);
            limits.max_image_height = Some(4096);
            limits.max_alloc = Some(64 * 1024 * 1024);
            reader.limits(limits);
            let decoded = reader.decode().map_err(|_| error("MEDIA_IMAGE_INVALID"))?;
            let (width, height) = decoded.dimensions();
            (media_type, width, height, None)
        }
        MediaKind::Video => {
            let (width, height, duration) =
                mp4_metadata(bytes).ok_or(error("MEDIA_VIDEO_INVALID"))?;
            ("video/mp4", width, height, Some(duration))
        }
    };
    Ok(MediaAssetMetadata {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        media_type: media_type.into(),
        byte_length: bytes.len(),
        width,
        height,
        duration_millis,
    })
}

fn be32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
fn be64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn mp4_boxes(bytes: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let mut offset = 0usize;
    let mut boxes = Vec::new();
    while offset < bytes.len() {
        if boxes.len() >= 4096 {
            return None;
        }
        let size = be32(bytes, offset)?;
        let header = if size == 1 { 16 } else { 8 };
        let size = match size {
            0 => bytes.len() - offset,
            1 => usize::try_from(be64(bytes, offset + 8)?).ok()?,
            n => n as usize,
        };
        if size < header || size > bytes.len() - offset {
            return None;
        }
        boxes.push((
            bytes.get(offset + 4..offset + 8)?,
            bytes.get(offset + header..offset + size)?,
        ));
        offset += size;
    }
    Some(boxes)
}

fn mp4_box(bytes: &[u8], wanted: [u8; 4]) -> Option<&[u8]> {
    mp4_boxes(bytes)?
        .into_iter()
        .find_map(|(kind, body)| (kind == wanted).then_some(body))
}

fn mp4_metadata(bytes: &[u8]) -> Option<(u32, u32, u64)> {
    mp4_box(bytes, *b"ftyp")?;
    if mp4_box(bytes, *b"mdat")?.is_empty() {
        return None;
    }
    let moov = mp4_box(bytes, *b"moov")?;
    let mvhd = mp4_box(moov, *b"mvhd")?;
    let (scale, duration) = match mvhd.first()? {
        0 => (be32(mvhd, 12)?, u64::from(be32(mvhd, 16)?)),
        1 => (be32(mvhd, 20)?, be64(mvhd, 24)?),
        _ => return None,
    };
    if scale == 0 {
        return None;
    }
    let track = mp4_boxes(moov)?
        .into_iter()
        .filter(|(kind, _)| *kind == b"trak")
        .find_map(|(_, track)| {
            let mdia = mp4_box(track, *b"mdia")?;
            (mp4_box(mdia, *b"hdlr")?.get(8..12)? == b"vide").then_some(track)
        })?;
    let tkhd = mp4_box(track, *b"tkhd")?;
    let offset = match tkhd.first()? {
        0 => 76,
        1 => 88,
        _ => return None,
    };
    let width = be32(tkhd, offset)? >> 16;
    let height = be32(tkhd, offset + 4)? >> 16;
    if width == 0 || height == 0 {
        return None;
    }
    Some((
        width,
        height,
        duration.checked_mul(1000)? / u64::from(scale),
    ))
}

#[cfg(test)]
mod tests;
