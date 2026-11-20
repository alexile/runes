//! Speech, images and transcription: speak a sentence, transcribe it back,
//! then draw a picture of it.
//!
//! Run with `OPENAI_API_KEY=... cargo run -p rune-chain --example multimodal`.
//! Writes `speech.mp3` and `image-0.png` to the current directory.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use rune_chain::openai;
use rune_chain::prelude::*;
use rune_chain::{AudioFormat, GeneratedImage, TimestampGranularity, TranscriptionFormat};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = openai::Client::from_env()?;

    // Text to speech.
    let tts = client.speech_model("gpt-4o-mini-tts");
    let speech = tts
        .synthesize(
            &SpeechRequest::new("A lighthouse stands on a rocky island at dusk.", "coral")
                .format(AudioFormat::Mp3)
                .instructions("Calm and slow, like a documentary narrator."),
        )
        .await?;
    std::fs::write("speech.mp3", &speech.audio)?;
    println!("wrote speech.mp3 ({} bytes)", speech.audio.len());

    // Speech to text, with word timestamps.
    let whisper = client.transcription_model("whisper-1");
    let transcript = whisper
        .transcribe(
            &TranscriptionRequest::new(speech.audio, "speech.mp3")
                .language("en")
                .response_format(TranscriptionFormat::VerboseJson)
                .timestamp_granularity(TimestampGranularity::Word),
        )
        .await?;
    println!("transcript: {}", transcript.text);
    for word in transcript.words.iter().take(5) {
        println!("  {:>5.2}s  {}", word.start, word.text);
    }

    // Text to image.
    let painter = client.image_generation_model("gpt-image-1");
    let images = painter
        .generate_image(
            &ImageGenerationRequest::new(transcript.text)
                .size("1024x1024")
                .quality("low"),
        )
        .await?;
    for (i, image) in images.images.iter().enumerate() {
        match image {
            GeneratedImage::Bytes { data, mime_type } => {
                let path = format!("image-{i}.png");
                std::fs::write(&path, data)?;
                println!("wrote {path} ({mime_type}, {} bytes)", data.len());
            }
            GeneratedImage::Url { url } => println!("image {i}: {url}"),
            _ => {}
        }
    }
    Ok(())
}
