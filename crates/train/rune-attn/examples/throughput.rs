//! Rough throughput check:
//! `cargo run --release -p rune-attn --example throughput [seq] [block_q] [block_k]`.
#![allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::many_single_char_names
)]

use std::time::Instant;

use rune_attn::{Attention, AttnError, AttnInputs, AttnLayout, HeadDims};

fn main() -> Result<(), AttnError> {
    let mut args = std::env::args().skip(1).map(|a| a.parse::<usize>().ok());
    let seq = args.next().flatten().unwrap_or(2048);
    let bq = args.next().flatten().unwrap_or(rune_attn::DEFAULT_BLOCK_Q);
    let bk = args.next().flatten().unwrap_or(rune_attn::DEFAULT_BLOCK_K);
    let layout = AttnLayout::dense(1, seq, seq, HeadDims::new(16, 4, 128, 128))?;
    let fill = |n: usize, f: f32| (0..n).map(|i| (i as f32 * f).sin()).collect::<Vec<f32>>();
    let (q, k, v) = (
        fill(layout.q_len(), 0.37),
        fill(layout.k_len(), 0.11),
        fill(layout.v_len(), 0.07),
    );
    let d_out = fill(layout.out_len(), 0.05);
    let inputs = AttnInputs::new(&q, &k, &v);
    let attn = Attention::new().causal(true).blocks(bq, bk);
    let fwd = attn.forward(&layout, &inputs)?; // warm up
    let reps = 3;
    let t = Instant::now();
    for _ in 0..reps {
        attn.forward(&layout, &inputs)?;
    }
    let f = t.elapsed().as_secs_f64() / f64::from(reps);
    let t = Instant::now();
    for _ in 0..reps {
        attn.backward(&layout, &inputs, &fwd.out, &fwd.lse, &d_out)?;
    }
    let b = t.elapsed().as_secs_f64() / f64::from(reps);
    // Causal: half of the 4·s²·d multiply-adds per head (QKᵀ and PV).
    let flops = 2.0 * 2.0 * (seq * seq) as f64 * 128.0 * 16.0 / 2.0;
    println!(
        "seq {seq}, 16q/4kv heads, dim 128, causal, blocks {bq}x{bk}: forward {:.1} ms ({:.0} tok/s, {:.1} GFLOP/s), backward {:.1} ms ({:.0} tok/s), fwd+bwd {:.0} tok/s",
        f * 1e3,
        seq as f64 / f,
        flops / f / 1e9,
        b * 1e3,
        seq as f64 / b,
        seq as f64 / (f + b)
    );
    Ok(())
}
