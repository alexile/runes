//! `max_len` must cap the memory a render holds, not only its result.

#![allow(unsafe_code, reason = "a counting allocator for the test")]
#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use rune_chain_core::{Message, PromptArgs};
use rune_chain_prompt::{
    ChatTemplate, MessageTemplate, MessagesPlaceholder, StringTemplate, TemplateError,
    messages_value,
};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        PEAK.fetch_max(live, Ordering::SeqCst);
        // SAFETY: same layout the caller gave us.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: `ptr` came from `alloc` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Extra bytes allocated at the peak of `f`, above what was live before.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f();
    (out, PEAK.load(Ordering::SeqCst) - base)
}

const MB: usize = 1 << 20;

// One test only: the counters are global, so parallel tests would mix.
#[test]
fn max_len_bounds_peak_memory() {
    let big = "x".repeat(MB);

    let mut args = PromptArgs::new();
    args.insert("x".into(), big.clone().into());
    let tmpl = StringTemplate::new("{x}{x}{x}{x}{x}{x}{x}{x}").with_max_len(10);
    let (res, peak) = peak_during(|| tmpl.try_format(&args));
    assert_eq!(
        res.unwrap_err(),
        TemplateError::TooLong {
            len: 8 * MB,
            max: 10
        }
    );
    assert!(peak < MB / 2, "string template peaked at {peak} bytes");

    let history: Vec<Message> = (0..8).map(|_| Message::human(big.clone())).collect();
    let mut args = PromptArgs::new();
    args.insert("h".into(), messages_value(&history));
    drop(history);
    let chat = ChatTemplate::new(vec![MessageTemplate::system("s")])
        .with_placeholder(MessagesPlaceholder::new("h"))
        .with_max_len(10);
    let (res, peak) = peak_during(|| chat.try_format_messages(&args));
    assert_eq!(
        res.unwrap_err(),
        TemplateError::TooLong {
            len: 8 * MB + 1,
            max: 10
        }
    );
    assert!(peak < 3 * MB, "chat template peaked at {peak} bytes");
    let (res, peak) = peak_during(|| chat.render(&args));
    assert!(res.is_err());
    assert!(peak < 3 * MB, "chat render peaked at {peak} bytes");
}
