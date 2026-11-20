//! Property tests over random shapes and options.
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::suboptimal_flops,
    clippy::type_complexity,
    clippy::cast_precision_loss,
    clippy::many_single_char_names
)]

mod common;

use common::{BiasKind, Problem, Rng, Spec, assert_close, f32s};
use proptest::prelude::*;
use rune_attn::HeadDims;

fn spec_strategy() -> impl Strategy<Value = Spec> {
    (
        any::<bool>(),
        proptest::option::of(0usize..5),
        proptest::option::of(0usize..5),
        proptest::option::of(1.0f64..10.0),
        0u8..3,
    )
        .prop_map(|(causal, left, right, softcap, b)| Spec {
            causal,
            left,
            right,
            softcap,
            scale: None,
            bias: [BiasKind::None, BiasKind::Alibi, BiasKind::Dense][usize::from(b)],
        })
}

fn problem_strategy()
-> impl Strategy<Value = (Vec<usize>, Vec<usize>, HeadDims, (usize, usize), u64)> {
    (
        proptest::collection::vec((0usize..10, 0usize..10), 1..4),
        1usize..3,
        1usize..3,
        1usize..7,
        1usize..7,
        (1usize..9, 1usize..9),
        any::<u64>(),
    )
        .prop_map(|(lens, hkv, group, dqk, dv, blocks, seed)| {
            let mut cu_q = vec![0];
            let mut cu_k = vec![0];
            for (a, b) in lens {
                cu_q.push(cu_q[cu_q.len() - 1] + a);
                cu_k.push(cu_k[cu_k.len() - 1] + b);
            }
            (
                cu_q,
                cu_k,
                HeadDims::new(hkv * group, hkv, dqk, dv),
                blocks,
                seed,
            )
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn forward_and_chunks_match_reference(spec in spec_strategy(), (cu_q, cu_k, hd, blocks, seed) in problem_strategy(), chunk in 1usize..6) {
        let mut rng = Rng::new(seed);
        let p = Problem::new(cu_q, cu_k, hd, &mut rng, 1.0);
        let attn = spec.attention(blocks);
        let got = p.forward(&spec, &attn);
        let (out, lse) = p.reference(&spec);
        assert_close("out", &got.out, &out, 2e-6, 2e-5);
        assert_close("lse", &got.lse, &lse, 2e-6, 2e-5);
        let (q, k, v, s, b) = p.f32_parts();
        let inputs = p.inputs(&spec, &q, &k, &v, &s, &b);
        let merged = attn.forward_kv_chunked(&p.layout(), &inputs, chunk).unwrap();
        assert_close("chunked out", &merged.out, &out, 1e-5, 1e-4);
        assert_close("chunked lse", &merged.lse, &lse, 1e-5, 1e-4);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    #[test]
    fn gradients_match_finite_differences(spec in spec_strategy(), (cu_q, cu_k, hd, blocks, seed) in problem_strategy()) {
        let mut rng = Rng::new(seed);
        let p = Problem::new(cu_q, cu_k, hd, &mut rng, 1.0);
        let w = rng.vec(p.reference(&spec).0.len(), 1.0);
        let (_, g) = p.backward(&spec, &spec.attention(blocks), &f32s(&w));
        let fd = p.fd_grads(&spec, &w);
        assert_close("dq", &g.dq, &fd[0], 1e-4, 1e-3);
        assert_close("dk", &g.dk, &fd[1], 1e-4, 1e-3);
        assert_close("dv", &g.dv, &fd[2], 1e-4, 1e-3);
        if spec.bias == BiasKind::Dense {
            assert_close("dbias", g.dbias.as_deref().unwrap_or_default(), &fd[3], 1e-4, 1e-3);
        }
    }
}
