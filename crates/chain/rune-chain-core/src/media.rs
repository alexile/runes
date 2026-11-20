//! Provider-agnostic speech-to-text, image generation and text-to-speech.
//!
//! Each capability is a small async trait with a request builder and a
//! plain response type:
//!
//! - [`TranscriptionModel`] — audio in, text (and segments / word
//!   timestamps when the provider reports them) out
//! - [`ImageGenerationModel`] — a prompt in, images as bytes or URLs out
//! - [`SpeechModel`] — text in, audio bytes out
//!
//! Failures are [`LlmError`]s, so retry, fallback and error-kind handling
//! work the same as for chat models. `Debug` output of requests and
//! responses never dumps audio or image bytes, only their length.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{LlmError, LlmErrorKind};

fn invalid(message: impl Into<String>) -> LlmError {
    LlmError::new(LlmErrorKind::InvalidRequest, message)
}

/// Debug helper: shows `<N bytes>` instead of the payload.
struct ByteLen(usize);

impl fmt::Debug for ByteLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

// ── Transcription ────────────────────────────────────────────────────────────

/// The wire format a transcription is asked for.
///
/// Not every model supports every format; e.g. `OpenAI`'s
/// `gpt-4o-transcribe` accepts only [`Json`](Self::Json) and
/// [`Text`](Self::Text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TranscriptionFormat {
    /// `{"text": …}`.
    Json,
    /// Plain text.
    Text,
    /// JSON with language, duration, segments and (on request) words.
    VerboseJson,
    /// `SubRip` subtitles; the raw file ends up in
    /// [`TranscriptionResponse::text`].
    Srt,
    /// `WebVTT` subtitles; the raw file ends up in
    /// [`TranscriptionResponse::text`].
    Vtt,
}

impl TranscriptionFormat {
    /// The `OpenAI` wire name, e.g. `"verbose_json"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
            Self::VerboseJson => "verbose_json",
            Self::Srt => "srt",
            Self::Vtt => "vtt",
        }
    }
}

/// Timestamp detail requested with [`TranscriptionFormat::VerboseJson`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimestampGranularity {
    /// Per-word start and end times.
    Word,
    /// Per-segment start and end times.
    Segment,
}

impl TimestampGranularity {
    /// The wire name, `"word"` or `"segment"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Word => "word",
            Self::Segment => "segment",
        }
    }
}

/// An audio file to transcribe, plus options.
///
/// ```rust
/// use rune_chain_core::{TranscriptionFormat, TranscriptionRequest};
///
/// let req = TranscriptionRequest::new(vec![0u8; 16], "call.mp3")
///     .language("en")
///     .prompt("Speakers: Ada, Grace.")
///     .temperature(0.0)
///     .response_format(TranscriptionFormat::VerboseJson);
/// assert!(req.validate().is_ok());
/// assert_eq!(req.mime_type(), "audio/mpeg");
/// // Debug output shows the size, not the audio.
/// assert!(format!("{req:?}").contains("<16 bytes>"));
/// ```
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct TranscriptionRequest {
    /// The encoded audio file (mp3, wav, m4a, …).
    pub audio: Vec<u8>,
    /// The file name sent with the upload; providers use its extension to
    /// detect the format.
    pub filename: String,
    /// MIME type of [`audio`](Self::audio); guessed from the file extension
    /// when unset (see [`mime_type`](Self::mime_type)).
    pub mime: Option<String>,
    /// ISO-639-1 language of the audio, e.g. `"en"`; improves accuracy and
    /// latency.
    pub language: Option<String>,
    /// Text to guide the model's style or spelling of names.
    pub prompt: Option<String>,
    /// Sampling temperature, 0 to 1.
    pub temperature: Option<f32>,
    /// Requested output format (provider default when unset).
    pub response_format: Option<TranscriptionFormat>,
    /// Timestamp detail; only honoured with
    /// [`TranscriptionFormat::VerboseJson`].
    pub timestamp_granularities: Vec<TimestampGranularity>,
}

impl fmt::Debug for TranscriptionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranscriptionRequest")
            .field("audio", &ByteLen(self.audio.len()))
            .field("filename", &self.filename)
            .field("mime", &self.mime)
            .field("language", &self.language)
            .field("prompt", &self.prompt.as_ref().map(|p| ByteLen(p.len())))
            .field("temperature", &self.temperature)
            .field("response_format", &self.response_format)
            .field("timestamp_granularities", &self.timestamp_granularities)
            .finish()
    }
}

impl TranscriptionRequest {
    /// A request for `audio`, uploaded as `filename` (e.g. `"memo.m4a"`).
    pub fn new(audio: impl Into<Vec<u8>>, filename: impl Into<String>) -> Self {
        Self {
            audio: audio.into(),
            filename: filename.into(),
            mime: None,
            language: None,
            prompt: None,
            temperature: None,
            response_format: None,
            timestamp_granularities: Vec::new(),
        }
    }

    /// Set the audio MIME type explicitly.
    #[must_use]
    pub fn mime(mut self, mime: impl Into<String>) -> Self {
        self.mime = Some(mime.into());
        self
    }

    /// Set the spoken language (ISO-639-1, e.g. `"de"`).
    #[must_use]
    pub fn language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }

    /// Set a guiding prompt.
    #[must_use]
    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Set the sampling temperature.
    #[must_use]
    pub const fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set the output format.
    #[must_use]
    pub const fn response_format(mut self, format: TranscriptionFormat) -> Self {
        self.response_format = Some(format);
        self
    }

    /// Ask for timestamps at `granularity` (repeatable).
    #[must_use]
    pub fn timestamp_granularity(mut self, granularity: TimestampGranularity) -> Self {
        if !self.timestamp_granularities.contains(&granularity) {
            self.timestamp_granularities.push(granularity);
        }
        self
    }

    /// The MIME type: [`mime`](Self::mime) if set, else a guess from the
    /// file extension, else `application/octet-stream`.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        if let Some(mime) = &self.mime {
            return mime;
        }
        let ext = self
            .filename
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .unwrap_or_default();
        match ext.as_str() {
            "mp3" | "mpga" | "mpeg" => "audio/mpeg",
            "mp4" | "m4a" => "audio/mp4",
            "wav" => "audio/wav",
            "webm" => "audio/webm",
            "ogg" | "oga" => "audio/ogg",
            "opus" => "audio/opus",
            "flac" => "audio/flac",
            "aac" => "audio/aac",
            _ => "application/octet-stream",
        }
    }

    /// Provider-independent checks: non-empty audio and file name, a
    /// temperature in `0..=1`, and no control characters in the text
    /// fields that end up in multipart headers.
    ///
    /// # Errors
    ///
    /// An [`LlmErrorKind::InvalidRequest`] error naming the bad field.
    pub fn validate(&self) -> Result<(), LlmError> {
        if self.audio.is_empty() {
            return Err(invalid("transcription audio is empty"));
        }
        if self.filename.trim().is_empty() {
            return Err(invalid("transcription file name is empty"));
        }
        if let Some(t) = self.temperature
            && !(0.0..=1.0).contains(&t)
        {
            return Err(invalid("transcription temperature must be between 0 and 1"));
        }
        if let Some(mime) = &self.mime
            && (mime.is_empty() || mime.chars().any(char::is_control))
        {
            return Err(invalid("invalid audio MIME type"));
        }
        if let Some(lang) = &self.language
            && (lang.is_empty()
                || lang.len() > 16
                || !lang.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        {
            return Err(invalid("language must be a short code such as `en`"));
        }
        Ok(())
    }
}

/// A stretch of transcribed speech with its time range.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TranscriptionSegment {
    /// Start, in seconds from the beginning of the audio.
    pub start: f64,
    /// End, in seconds.
    pub end: f64,
    /// The text spoken in this range.
    pub text: String,
}

impl TranscriptionSegment {
    /// A segment from `start` to `end` seconds.
    pub fn new(start: f64, end: f64, text: impl Into<String>) -> Self {
        Self {
            start,
            end,
            text: text.into(),
        }
    }
}

/// The result of a [`TranscriptionModel::transcribe`] call.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct TranscriptionResponse {
    /// The full transcript (or the raw subtitle file for SRT / VTT).
    pub text: String,
    /// Detected or given language, when reported.
    pub language: Option<String>,
    /// Audio duration in seconds, when reported.
    pub duration: Option<f64>,
    /// Segment timestamps, when reported.
    pub segments: Vec<TranscriptionSegment>,
    /// Word timestamps, when reported.
    pub words: Vec<TranscriptionSegment>,
}

impl TranscriptionResponse {
    /// A response holding only `text`.
    pub fn from_text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    /// Set the language (builder style).
    #[must_use]
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }

    /// Set the duration (builder style).
    #[must_use]
    pub const fn with_duration(mut self, seconds: f64) -> Self {
        self.duration = Some(seconds);
        self
    }

    /// Set the segments (builder style).
    #[must_use]
    pub fn with_segments(mut self, segments: Vec<TranscriptionSegment>) -> Self {
        self.segments = segments;
        self
    }

    /// Set the word timestamps (builder style).
    #[must_use]
    pub fn with_words(mut self, words: Vec<TranscriptionSegment>) -> Self {
        self.words = words;
        self
    }
}

/// A speech-to-text model.
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_core::{
///     LlmError, TranscriptionModel, TranscriptionRequest, TranscriptionResponse,
/// };
///
/// struct Fixed;
///
/// #[async_trait]
/// impl TranscriptionModel for Fixed {
///     async fn transcribe(
///         &self,
///         request: &TranscriptionRequest,
///     ) -> Result<TranscriptionResponse, LlmError> {
///         request.validate()?;
///         Ok(TranscriptionResponse::from_text("hello"))
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let out = Fixed
///     .transcribe(&TranscriptionRequest::new(vec![1, 2, 3], "a.wav"))
///     .await
///     .unwrap();
/// assert_eq!(out.text, "hello");
/// # });
/// ```
#[async_trait]
pub trait TranscriptionModel: Send + Sync {
    /// Transcribe the audio in `request`.
    async fn transcribe(
        &self,
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResponse, LlmError>;
}

#[async_trait]
impl<T: TranscriptionModel + ?Sized> TranscriptionModel for Arc<T> {
    async fn transcribe(
        &self,
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResponse, LlmError> {
        (**self).transcribe(request).await
    }
}

// ── Image generation ─────────────────────────────────────────────────────────

/// Encoding of generated images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ImageFormat {
    /// PNG.
    Png,
    /// JPEG.
    Jpeg,
    /// WebP.
    Webp,
}

impl ImageFormat {
    /// The wire name, e.g. `"png"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Webp => "webp",
        }
    }

    /// The MIME type, e.g. `"image/png"`.
    #[must_use]
    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }

    /// Detect the format from the first bytes of an image.
    ///
    /// ```rust
    /// use rune_chain_core::ImageFormat;
    ///
    /// assert_eq!(ImageFormat::sniff(b"\x89PNG\r\n\x1a\n...."), Some(ImageFormat::Png));
    /// assert_eq!(ImageFormat::sniff(b"hello"), None);
    /// ```
    #[must_use]
    pub fn sniff(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Self::Png)
        } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            Some(Self::Jpeg)
        } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            Some(Self::Webp)
        } else {
            None
        }
    }
}

/// How the provider should hand back images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ImageResponseFormat {
    /// A (usually short-lived) URL to download.
    Url,
    /// The image bytes inline (base64 on the wire).
    Bytes,
}

/// A prompt plus options for [`ImageGenerationModel::generate_image`].
///
/// `size`, `quality` and `style` are free-form strings because their
/// accepted values differ per model (e.g. `"1024x1024"` or `"auto"`;
/// `"hd"` for DALL·E 3, `"high"` for gpt-image).
///
/// ```rust
/// use rune_chain_core::{ImageFormat, ImageGenerationRequest};
///
/// let req = ImageGenerationRequest::new("A lighthouse at dusk, watercolour")
///     .size("1024x1024")
///     .n(2)
///     .quality("high")
///     .output_format(ImageFormat::Webp);
/// assert!(req.validate().is_ok());
/// assert!(ImageGenerationRequest::new("x").n(0).validate().is_err());
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ImageGenerationRequest {
    /// What to draw.
    pub prompt: String,
    /// Image size, e.g. `"1024x1024"`, `"1536x1024"` or `"auto"`; some
    /// providers take an aspect ratio such as `"16:9"`.
    pub size: Option<String>,
    /// How many images (provider default, usually 1, when unset).
    pub n: Option<u32>,
    /// Quality tier, e.g. `"standard"`, `"hd"`, `"low"`, `"high"`.
    pub quality: Option<String>,
    /// Style, e.g. `"vivid"` or `"natural"` (DALL·E 3).
    pub style: Option<String>,
    /// Encoding of the generated images.
    pub output_format: Option<ImageFormat>,
    /// URLs or inline bytes (provider default when unset).
    pub response_format: Option<ImageResponseFormat>,
}

impl ImageGenerationRequest {
    /// Most images a single request may ask for.
    pub const MAX_N: u32 = 10;

    /// A request to draw `prompt`.
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            size: None,
            n: None,
            quality: None,
            style: None,
            output_format: None,
            response_format: None,
        }
    }

    /// Set the size.
    #[must_use]
    pub fn size(mut self, size: impl Into<String>) -> Self {
        self.size = Some(size.into());
        self
    }

    /// Set the number of images.
    #[must_use]
    pub const fn n(mut self, n: u32) -> Self {
        self.n = Some(n);
        self
    }

    /// Set the quality tier.
    #[must_use]
    pub fn quality(mut self, quality: impl Into<String>) -> Self {
        self.quality = Some(quality.into());
        self
    }

    /// Set the style.
    #[must_use]
    pub fn style(mut self, style: impl Into<String>) -> Self {
        self.style = Some(style.into());
        self
    }

    /// Set the image encoding.
    #[must_use]
    pub const fn output_format(mut self, format: ImageFormat) -> Self {
        self.output_format = Some(format);
        self
    }

    /// Ask for URLs or inline bytes.
    #[must_use]
    pub const fn response_format(mut self, format: ImageResponseFormat) -> Self {
        self.response_format = Some(format);
        self
    }

    /// Provider-independent checks: a non-blank prompt and `n` in
    /// `1..=MAX_N` (see [`MAX_N`](Self::MAX_N)).
    ///
    /// # Errors
    ///
    /// An [`LlmErrorKind::InvalidRequest`] error naming the bad field.
    pub fn validate(&self) -> Result<(), LlmError> {
        if self.prompt.trim().is_empty() {
            return Err(invalid("image prompt is empty"));
        }
        if let Some(n) = self.n
            && !(1..=Self::MAX_N).contains(&n)
        {
            return Err(invalid(format!(
                "image count must be between 1 and {}",
                Self::MAX_N
            )));
        }
        Ok(())
    }
}

/// One generated image.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneratedImage {
    /// The image itself.
    Bytes {
        /// The encoded image.
        data: Vec<u8>,
        /// Its MIME type, e.g. `"image/png"`.
        mime_type: String,
    },
    /// A URL to download it from (often valid for a limited time).
    Url {
        /// The `https` URL.
        url: String,
    },
}

impl fmt::Debug for GeneratedImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes { data, mime_type } => f
                .debug_struct("Bytes")
                .field("data", &ByteLen(data.len()))
                .field("mime_type", mime_type)
                .finish(),
            Self::Url { url } => f.debug_struct("Url").field("url", url).finish(),
        }
    }
}

impl GeneratedImage {
    /// The bytes, if the image came inline.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes { data, .. } => Some(data),
            Self::Url { .. } => None,
        }
    }

    /// The URL, if the image came as a link.
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Url { url } => Some(url),
            Self::Bytes { .. } => None,
        }
    }
}

/// The result of an [`ImageGenerationModel::generate_image`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageGenerationResponse {
    /// The images, in provider order.
    pub images: Vec<GeneratedImage>,
    /// The prompt the provider actually used, if it rewrote it.
    pub revised_prompt: Option<String>,
}

impl ImageGenerationResponse {
    /// A response holding `images`.
    #[must_use]
    pub const fn new(images: Vec<GeneratedImage>) -> Self {
        Self {
            images,
            revised_prompt: None,
        }
    }

    /// Set the revised prompt (builder style).
    #[must_use]
    pub fn with_revised_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.revised_prompt = Some(prompt.into());
        self
    }
}

/// A text-to-image model.
#[async_trait]
pub trait ImageGenerationModel: Send + Sync {
    /// Generate images for `request`.
    async fn generate_image(
        &self,
        request: &ImageGenerationRequest,
    ) -> Result<ImageGenerationResponse, LlmError>;
}

#[async_trait]
impl<T: ImageGenerationModel + ?Sized> ImageGenerationModel for Arc<T> {
    async fn generate_image(
        &self,
        request: &ImageGenerationRequest,
    ) -> Result<ImageGenerationResponse, LlmError> {
        (**self).generate_image(request).await
    }
}

// ── Speech (TTS) ─────────────────────────────────────────────────────────────

/// Encoding of synthesized audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AudioFormat {
    /// MP3.
    Mp3,
    /// Opus in Ogg.
    Opus,
    /// AAC.
    Aac,
    /// FLAC.
    Flac,
    /// WAV (PCM in a RIFF container).
    Wav,
    /// Raw 16-bit little-endian PCM, no header.
    Pcm,
}

impl AudioFormat {
    /// The wire name, e.g. `"mp3"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mp3 => "mp3",
            Self::Opus => "opus",
            Self::Aac => "aac",
            Self::Flac => "flac",
            Self::Wav => "wav",
            Self::Pcm => "pcm",
        }
    }

    /// The MIME type, e.g. `"audio/mpeg"`.
    #[must_use]
    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::Mp3 => "audio/mpeg",
            Self::Opus => "audio/ogg",
            Self::Aac => "audio/aac",
            Self::Flac => "audio/flac",
            Self::Wav => "audio/wav",
            Self::Pcm => "audio/pcm",
        }
    }
}

/// Text plus voice settings for [`SpeechModel::synthesize`].
///
/// ```rust
/// use rune_chain_core::{AudioFormat, SpeechRequest};
///
/// let req = SpeechRequest::new("Your build passed.", "alloy")
///     .format(AudioFormat::Opus)
///     .speed(1.25)
///     .instructions("Cheerful, quick.");
/// assert!(req.validate().is_ok());
/// assert!(SpeechRequest::new("hi", "alloy").speed(f32::NAN).validate().is_err());
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SpeechRequest {
    /// The text to speak.
    pub text: String,
    /// The voice name, e.g. `"alloy"` or `"Kore"`.
    pub voice: String,
    /// Audio encoding (provider default when unset).
    pub format: Option<AudioFormat>,
    /// Playback speed multiplier, `1.0` being normal.
    pub speed: Option<f32>,
    /// Delivery instructions (tone, accent, pace) for models that take them.
    pub instructions: Option<String>,
}

impl SpeechRequest {
    /// Speak `text` with `voice`.
    pub fn new(text: impl Into<String>, voice: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            voice: voice.into(),
            format: None,
            speed: None,
            instructions: None,
        }
    }

    /// Set the audio encoding.
    #[must_use]
    pub const fn format(mut self, format: AudioFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Set the speed multiplier.
    #[must_use]
    pub const fn speed(mut self, speed: f32) -> Self {
        self.speed = Some(speed);
        self
    }

    /// Set delivery instructions.
    #[must_use]
    pub fn instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Provider-independent checks: non-blank text and voice and a finite,
    /// positive speed.
    ///
    /// # Errors
    ///
    /// An [`LlmErrorKind::InvalidRequest`] error naming the bad field.
    pub fn validate(&self) -> Result<(), LlmError> {
        if self.text.trim().is_empty() {
            return Err(invalid("speech text is empty"));
        }
        if self.voice.trim().is_empty() {
            return Err(invalid("speech voice is empty"));
        }
        if let Some(speed) = self.speed
            && !(speed.is_finite() && speed > 0.0)
        {
            return Err(invalid("speech speed must be a positive number"));
        }
        Ok(())
    }
}

/// Synthesized audio.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpeechResponse {
    /// The encoded audio.
    pub audio: Vec<u8>,
    /// Its MIME type, e.g. `"audio/mpeg"`.
    pub mime_type: String,
}

impl fmt::Debug for SpeechResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpeechResponse")
            .field("audio", &ByteLen(self.audio.len()))
            .field("mime_type", &self.mime_type)
            .finish()
    }
}

impl SpeechResponse {
    /// Audio bytes of the given MIME type.
    pub fn new(audio: Vec<u8>, mime_type: impl Into<String>) -> Self {
        Self {
            audio,
            mime_type: mime_type.into(),
        }
    }
}

/// A text-to-speech model.
#[async_trait]
pub trait SpeechModel: Send + Sync {
    /// Speak the text in `request`.
    async fn synthesize(&self, request: &SpeechRequest) -> Result<SpeechResponse, LlmError>;
}

#[async_trait]
impl<T: SpeechModel + ?Sized> SpeechModel for Arc<T> {
    async fn synthesize(&self, request: &SpeechRequest) -> Result<SpeechResponse, LlmError> {
        (**self).synthesize(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    #[async_trait]
    impl TranscriptionModel for Echo {
        async fn transcribe(
            &self,
            r: &TranscriptionRequest,
        ) -> Result<TranscriptionResponse, LlmError> {
            r.validate()?;
            Ok(TranscriptionResponse::from_text(r.filename.clone()))
        }
    }

    #[async_trait]
    impl ImageGenerationModel for Echo {
        async fn generate_image(
            &self,
            r: &ImageGenerationRequest,
        ) -> Result<ImageGenerationResponse, LlmError> {
            r.validate()?;
            Ok(ImageGenerationResponse::new(vec![GeneratedImage::Url {
                url: "https://example.com/a.png".into(),
            }])
            .with_revised_prompt(r.prompt.clone()))
        }
    }

    #[async_trait]
    impl SpeechModel for Echo {
        async fn synthesize(&self, r: &SpeechRequest) -> Result<SpeechResponse, LlmError> {
            r.validate()?;
            Ok(SpeechResponse::new(r.text.as_bytes().to_vec(), "audio/pcm"))
        }
    }

    #[test]
    fn arc_and_dyn_forward() {
        tokio_test::block_on(async {
            let t: Arc<dyn TranscriptionModel> = Arc::new(Echo);
            let out = t
                .transcribe(&TranscriptionRequest::new(vec![1], "x.wav"))
                .await
                .unwrap();
            assert_eq!(out.text, "x.wav");

            let i: Arc<dyn ImageGenerationModel> = Arc::new(Echo);
            let out = i
                .generate_image(&ImageGenerationRequest::new("cat"))
                .await
                .unwrap();
            assert_eq!(out.revised_prompt.as_deref(), Some("cat"));
            assert_eq!(out.images[0].url(), Some("https://example.com/a.png"));

            let s = Arc::new(Echo);
            let out = s.synthesize(&SpeechRequest::new("hi", "v")).await.unwrap();
            assert_eq!(out.audio, b"hi");
        });
    }

    #[test]
    fn transcription_validation() {
        let ok = TranscriptionRequest::new(vec![1], "a.mp3");
        assert!(ok.validate().is_ok());
        for bad in [
            TranscriptionRequest::new(Vec::new(), "a.mp3"),
            TranscriptionRequest::new(vec![1], "  "),
            ok.clone().temperature(1.5),
            ok.clone().temperature(f32::NAN),
            ok.clone().mime("audio/mpeg\r\nX-Evil: 1"),
            ok.language("en\"; x"),
        ] {
            let e = bad.validate().unwrap_err();
            assert_eq!(e.kind(), LlmErrorKind::InvalidRequest, "{bad:?}");
        }
    }

    #[test]
    fn mime_guessing() {
        let m = |name: &str| {
            TranscriptionRequest::new(vec![1], name)
                .mime_type()
                .to_string()
        };
        assert_eq!(m("a.MP3"), "audio/mpeg");
        assert_eq!(m("a.m4a"), "audio/mp4");
        assert_eq!(m("a.wav"), "audio/wav");
        assert_eq!(m("noext"), "application/octet-stream");
        let explicit = TranscriptionRequest::new(vec![1], "a.bin").mime("audio/webm");
        assert_eq!(explicit.mime_type(), "audio/webm");
    }

    #[test]
    fn granularities_dedupe() {
        let r = TranscriptionRequest::new(vec![1], "a.wav")
            .timestamp_granularity(TimestampGranularity::Word)
            .timestamp_granularity(TimestampGranularity::Word)
            .timestamp_granularity(TimestampGranularity::Segment);
        assert_eq!(r.timestamp_granularities.len(), 2);
    }

    #[test]
    fn image_and_speech_validation() {
        assert!(ImageGenerationRequest::new(" ").validate().is_err());
        assert!(ImageGenerationRequest::new("x").n(11).validate().is_err());
        assert!(ImageGenerationRequest::new("x").n(10).validate().is_ok());
        assert!(SpeechRequest::new("", "v").validate().is_err());
        assert!(SpeechRequest::new("t", "").validate().is_err());
        assert!(SpeechRequest::new("t", "v").speed(0.0).validate().is_err());
        assert!(
            SpeechRequest::new("t", "v")
                .speed(f32::INFINITY)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn debug_never_dumps_payloads() {
        let img = GeneratedImage::Bytes {
            data: vec![7; 1000],
            mime_type: "image/png".into(),
        };
        assert!(format!("{img:?}").contains("<1000 bytes>"));
        let speech = SpeechResponse::new(vec![1; 5], "audio/mpeg");
        assert!(format!("{speech:?}").contains("<5 bytes>"));
        let req = TranscriptionRequest::new(vec![1; 3], "a.wav").prompt("secret names");
        assert!(!format!("{req:?}").contains("secret"));
    }

    #[test]
    fn sniffs_formats() {
        assert_eq!(
            ImageFormat::sniff(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some(ImageFormat::Jpeg)
        );
        assert_eq!(
            ImageFormat::sniff(b"RIFF\0\0\0\0WEBPVP8 "),
            Some(ImageFormat::Webp)
        );
        assert_eq!(ImageFormat::sniff(b"RIFF\0\0\0\0WAVE"), None);
        assert_eq!(ImageFormat::Webp.mime_type(), "image/webp");
        assert_eq!(AudioFormat::Mp3.mime_type(), "audio/mpeg");
        assert_eq!(TranscriptionFormat::VerboseJson.as_str(), "verbose_json");
    }
}
