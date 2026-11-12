//! CVSS v4.0 scoring data, vendored from the FIRST reference calculator.
//!
//! Source: <https://github.com/FIRSTdotorg/cvss-v4-calculator>, commit
//! `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a` (2024-08-19):
//! `cvss_lookup.js` (the `MacroVector` scores), `max_composed.js` (the
//! highest-severity vectors of each `MacroVector`) and `max_severity.js` (the
//! depth of each `MacroVector`). The values are copied unchanged; only the
//! layout differs (arrays indexed by EQ level instead of string keys).
//!
//! The original files carry this notice, which is reproduced here as their
//! licence requires:
//!
//! ```text
//! Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
//!
//! Redistribution and use in source and binary forms, with or without
//! modification, are permitted provided that the following conditions are met:
//!
//! 1. Redistributions of source code must retain the above copyright notice, this
//!    list of conditions and the following disclaimer.
//!
//! 2. Redistributions in binary form must reproduce the above copyright notice,
//!    this list of conditions and the following disclaimer in the documentation
//!    and/or other materials provided with the distribution.
//!
//! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//! AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//! IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//! DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//! FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//! DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//! SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//! CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//! OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//! OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! ```
//!
//! SPDX-License-Identifier: BSD-2-Clause

/// The number of `MacroVector` slots: 3 × 2 × 3 × 3 × 3 × 2 EQ levels.
pub(super) const MACROVECTOR_SLOTS: usize = 324;

/// The score of every `MacroVector` (`cvss_lookup.js`), indexed by
/// [`super::MacroVector::index`]. `None` marks the 54 combinations that
/// cannot occur (EQ3 = 2 with EQ6 = 0) and have no entry upstream.
pub(super) const MACROVECTOR_SCORES: [Option<f64>; MACROVECTOR_SLOTS] = [
    Some(10.0), // 000000
    Some(9.9),  // 000001
    Some(9.8),  // 000010
    Some(9.5),  // 000011
    Some(9.5),  // 000020
    Some(9.2),  // 000021
    Some(10.0), // 000100
    Some(9.6),  // 000101
    Some(9.3),  // 000110
    Some(8.7),  // 000111
    Some(9.1),  // 000120
    Some(8.1),  // 000121
    Some(9.3),  // 000200
    Some(9.0),  // 000201
    Some(8.9),  // 000210
    Some(8.0),  // 000211
    Some(8.1),  // 000220
    Some(6.8),  // 000221
    Some(9.8),  // 001000
    Some(9.5),  // 001001
    Some(9.5),  // 001010
    Some(9.2),  // 001011
    Some(9.0),  // 001020
    Some(8.4),  // 001021
    Some(9.3),  // 001100
    Some(9.2),  // 001101
    Some(8.9),  // 001110
    Some(8.1),  // 001111
    Some(8.1),  // 001120
    Some(6.5),  // 001121
    Some(8.8),  // 001200
    Some(8.0),  // 001201
    Some(7.8),  // 001210
    Some(7.0),  // 001211
    Some(6.9),  // 001220
    Some(4.8),  // 001221
    None,       // 002000
    Some(9.2),  // 002001
    None,       // 002010
    Some(8.2),  // 002011
    None,       // 002020
    Some(7.2),  // 002021
    None,       // 002100
    Some(7.9),  // 002101
    None,       // 002110
    Some(6.9),  // 002111
    None,       // 002120
    Some(5.0),  // 002121
    None,       // 002200
    Some(6.9),  // 002201
    None,       // 002210
    Some(5.5),  // 002211
    None,       // 002220
    Some(2.7),  // 002221
    Some(9.9),  // 010000
    Some(9.7),  // 010001
    Some(9.5),  // 010010
    Some(9.2),  // 010011
    Some(9.2),  // 010020
    Some(8.5),  // 010021
    Some(9.5),  // 010100
    Some(9.1),  // 010101
    Some(9.0),  // 010110
    Some(8.3),  // 010111
    Some(8.4),  // 010120
    Some(7.1),  // 010121
    Some(9.2),  // 010200
    Some(8.1),  // 010201
    Some(8.2),  // 010210
    Some(7.1),  // 010211
    Some(7.2),  // 010220
    Some(5.3),  // 010221
    Some(9.5),  // 011000
    Some(9.3),  // 011001
    Some(9.2),  // 011010
    Some(8.5),  // 011011
    Some(8.5),  // 011020
    Some(7.3),  // 011021
    Some(9.2),  // 011100
    Some(8.2),  // 011101
    Some(8.0),  // 011110
    Some(7.2),  // 011111
    Some(7.0),  // 011120
    Some(5.9),  // 011121
    Some(8.4),  // 011200
    Some(7.0),  // 011201
    Some(7.1),  // 011210
    Some(5.2),  // 011211
    Some(5.0),  // 011220
    Some(3.0),  // 011221
    None,       // 012000
    Some(8.6),  // 012001
    None,       // 012010
    Some(7.5),  // 012011
    None,       // 012020
    Some(5.2),  // 012021
    None,       // 012100
    Some(7.1),  // 012101
    None,       // 012110
    Some(5.2),  // 012111
    None,       // 012120
    Some(2.9),  // 012121
    None,       // 012200
    Some(6.3),  // 012201
    None,       // 012210
    Some(2.9),  // 012211
    None,       // 012220
    Some(1.7),  // 012221
    Some(9.8),  // 100000
    Some(9.5),  // 100001
    Some(9.4),  // 100010
    Some(8.7),  // 100011
    Some(9.1),  // 100020
    Some(8.1),  // 100021
    Some(9.4),  // 100100
    Some(8.9),  // 100101
    Some(8.6),  // 100110
    Some(7.4),  // 100111
    Some(7.7),  // 100120
    Some(6.4),  // 100121
    Some(8.7),  // 100200
    Some(7.5),  // 100201
    Some(7.4),  // 100210
    Some(6.3),  // 100211
    Some(6.3),  // 100220
    Some(4.9),  // 100221
    Some(9.4),  // 101000
    Some(8.9),  // 101001
    Some(8.8),  // 101010
    Some(7.7),  // 101011
    Some(7.6),  // 101020
    Some(6.7),  // 101021
    Some(8.6),  // 101100
    Some(7.6),  // 101101
    Some(7.4),  // 101110
    Some(5.8),  // 101111
    Some(5.9),  // 101120
    Some(5.0),  // 101121
    Some(7.2),  // 101200
    Some(5.7),  // 101201
    Some(5.7),  // 101210
    Some(5.2),  // 101211
    Some(5.2),  // 101220
    Some(2.5),  // 101221
    None,       // 102000
    Some(8.3),  // 102001
    None,       // 102010
    Some(7.0),  // 102011
    None,       // 102020
    Some(5.4),  // 102021
    None,       // 102100
    Some(6.5),  // 102101
    None,       // 102110
    Some(5.8),  // 102111
    None,       // 102120
    Some(2.6),  // 102121
    None,       // 102200
    Some(5.3),  // 102201
    None,       // 102210
    Some(2.1),  // 102211
    None,       // 102220
    Some(1.3),  // 102221
    Some(9.5),  // 110000
    Some(9.0),  // 110001
    Some(8.8),  // 110010
    Some(7.6),  // 110011
    Some(7.6),  // 110020
    Some(7.0),  // 110021
    Some(9.0),  // 110100
    Some(7.7),  // 110101
    Some(7.5),  // 110110
    Some(6.2),  // 110111
    Some(6.1),  // 110120
    Some(5.3),  // 110121
    Some(7.7),  // 110200
    Some(6.6),  // 110201
    Some(6.8),  // 110210
    Some(5.9),  // 110211
    Some(5.2),  // 110220
    Some(3.0),  // 110221
    Some(8.9),  // 111000
    Some(7.8),  // 111001
    Some(7.6),  // 111010
    Some(6.7),  // 111011
    Some(6.2),  // 111020
    Some(5.8),  // 111021
    Some(7.4),  // 111100
    Some(5.9),  // 111101
    Some(5.7),  // 111110
    Some(5.7),  // 111111
    Some(4.7),  // 111120
    Some(2.3),  // 111121
    Some(6.1),  // 111200
    Some(5.2),  // 111201
    Some(5.7),  // 111210
    Some(2.9),  // 111211
    Some(2.4),  // 111220
    Some(1.6),  // 111221
    None,       // 112000
    Some(7.1),  // 112001
    None,       // 112010
    Some(5.9),  // 112011
    None,       // 112020
    Some(3.0),  // 112021
    None,       // 112100
    Some(5.8),  // 112101
    None,       // 112110
    Some(2.6),  // 112111
    None,       // 112120
    Some(1.5),  // 112121
    None,       // 112200
    Some(2.3),  // 112201
    None,       // 112210
    Some(1.3),  // 112211
    None,       // 112220
    Some(0.6),  // 112221
    Some(9.3),  // 200000
    Some(8.7),  // 200001
    Some(8.6),  // 200010
    Some(7.2),  // 200011
    Some(7.5),  // 200020
    Some(5.8),  // 200021
    Some(8.6),  // 200100
    Some(7.4),  // 200101
    Some(7.4),  // 200110
    Some(6.1),  // 200111
    Some(5.6),  // 200120
    Some(3.4),  // 200121
    Some(7.0),  // 200200
    Some(5.4),  // 200201
    Some(5.2),  // 200210
    Some(4.0),  // 200211
    Some(4.0),  // 200220
    Some(2.2),  // 200221
    Some(8.5),  // 201000
    Some(7.5),  // 201001
    Some(7.4),  // 201010
    Some(5.5),  // 201011
    Some(6.2),  // 201020
    Some(5.1),  // 201021
    Some(7.2),  // 201100
    Some(5.7),  // 201101
    Some(5.5),  // 201110
    Some(4.1),  // 201111
    Some(4.6),  // 201120
    Some(1.9),  // 201121
    Some(5.3),  // 201200
    Some(3.6),  // 201201
    Some(3.4),  // 201210
    Some(1.9),  // 201211
    Some(1.9),  // 201220
    Some(0.8),  // 201221
    None,       // 202000
    Some(6.4),  // 202001
    None,       // 202010
    Some(5.1),  // 202011
    None,       // 202020
    Some(2.0),  // 202021
    None,       // 202100
    Some(4.7),  // 202101
    None,       // 202110
    Some(2.1),  // 202111
    None,       // 202120
    Some(1.1),  // 202121
    None,       // 202200
    Some(2.4),  // 202201
    None,       // 202210
    Some(0.9),  // 202211
    None,       // 202220
    Some(0.4),  // 202221
    Some(8.8),  // 210000
    Some(7.5),  // 210001
    Some(7.3),  // 210010
    Some(5.3),  // 210011
    Some(6.0),  // 210020
    Some(5.0),  // 210021
    Some(7.3),  // 210100
    Some(5.5),  // 210101
    Some(5.9),  // 210110
    Some(4.0),  // 210111
    Some(4.1),  // 210120
    Some(2.0),  // 210121
    Some(5.4),  // 210200
    Some(4.3),  // 210201
    Some(4.5),  // 210210
    Some(2.2),  // 210211
    Some(2.0),  // 210220
    Some(1.1),  // 210221
    Some(7.5),  // 211000
    Some(5.5),  // 211001
    Some(5.8),  // 211010
    Some(4.5),  // 211011
    Some(4.0),  // 211020
    Some(2.1),  // 211021
    Some(6.1),  // 211100
    Some(5.1),  // 211101
    Some(4.8),  // 211110
    Some(1.8),  // 211111
    Some(2.0),  // 211120
    Some(0.9),  // 211121
    Some(4.6),  // 211200
    Some(1.8),  // 211201
    Some(1.7),  // 211210
    Some(0.7),  // 211211
    Some(0.8),  // 211220
    Some(0.2),  // 211221
    None,       // 212000
    Some(5.3),  // 212001
    None,       // 212010
    Some(2.4),  // 212011
    None,       // 212020
    Some(1.4),  // 212021
    None,       // 212100
    Some(2.4),  // 212101
    None,       // 212110
    Some(1.2),  // 212111
    None,       // 212120
    Some(0.5),  // 212121
    None,       // 212200
    Some(1.0),  // 212201
    None,       // 212210
    Some(0.3),  // 212211
    None,       // 212220
    Some(0.1),  // 212221
];

/// Severity level of a metric value within its EQ, as in the reference
/// `cvss_score.js` (`AV_levels`, `PR_levels`, ...). Lower is more severe.
pub(super) mod level {
    /// AV: N, A, L, P.
    pub const AV: [f64; 4] = [0.0, 0.1, 0.2, 0.3];
    /// PR: N, L, H.
    pub const PR: [f64; 3] = [0.0, 0.1, 0.2];
    /// UI: N, P, A.
    pub const UI: [f64; 3] = [0.0, 0.1, 0.2];
    /// AC: L, H.
    pub const AC: [f64; 2] = [0.0, 0.1];
    /// AT: N, P.
    pub const AT: [f64; 2] = [0.0, 0.1];
    /// VC, VI, VA: H, L, N.
    pub const VULNERABLE: [f64; 3] = [0.0, 0.1, 0.2];
    /// SC: H, L, N.
    pub const SC: [f64; 3] = [0.1, 0.2, 0.3];
    /// SI, SA: S, H, L, N.
    pub const SI_SA: [f64; 4] = [0.0, 0.1, 0.2, 0.3];
    /// CR, IR, AR: H, M, L.
    pub const REQUIREMENT: [f64; 3] = [0.0, 0.1, 0.2];
}

// The highest-severity vectors of each MacroVector (`max_composed.js`), as
// level indexes into the `level` arrays above, in the upstream order (the
// first match wins, so the order matters).

/// EQ1 maxima as (AV, PR, UI), by EQ1 level.
pub(super) const MAX_EQ1: [&[[u8; 3]]; 3] = [
    &[[0, 0, 0]],                       // AV:N/PR:N/UI:N
    &[[1, 0, 0], [0, 1, 0], [0, 0, 1]], // AV:A/PR:N/UI:N, AV:N/PR:L/UI:N, AV:N/PR:N/UI:P
    &[[3, 0, 0], [1, 1, 1]],            // AV:P/PR:N/UI:N, AV:A/PR:L/UI:P
];

/// EQ2 maxima as (AC, AT), by EQ2 level.
pub(super) const MAX_EQ2: [&[[u8; 2]]; 2] = [
    &[[0, 0]],         // AC:L/AT:N
    &[[1, 0], [0, 1]], // AC:H/AT:N, AC:L/AT:P
];

/// EQ3+EQ6 maxima as (VC, VI, VA, CR, IR, AR), by EQ3 then EQ6 level.
/// Impacts index H, L, N; requirements index H, M, L.
pub(super) const MAX_EQ3_EQ6: [[&[[u8; 6]]; 2]; 3] = [
    [
        &[[0, 0, 0, 0, 0, 0]], // VC:H/VI:H/VA:H/CR:H/IR:H/AR:H
        &[
            [0, 0, 1, 1, 1, 0], // VC:H/VI:H/VA:L/CR:M/IR:M/AR:H
            [0, 0, 0, 1, 1, 1], // VC:H/VI:H/VA:H/CR:M/IR:M/AR:M
        ],
    ],
    [
        &[
            [1, 0, 0, 0, 0, 0], // VC:L/VI:H/VA:H/CR:H/IR:H/AR:H
            [0, 1, 0, 0, 0, 0], // VC:H/VI:L/VA:H/CR:H/IR:H/AR:H
        ],
        &[
            [1, 0, 1, 0, 1, 0], // VC:L/VI:H/VA:L/CR:H/IR:M/AR:H
            [1, 0, 0, 0, 1, 1], // VC:L/VI:H/VA:H/CR:H/IR:M/AR:M
            [0, 1, 0, 1, 0, 1], // VC:H/VI:L/VA:H/CR:M/IR:H/AR:M
            [0, 1, 1, 1, 0, 0], // VC:H/VI:L/VA:L/CR:M/IR:H/AR:H
            [1, 1, 0, 0, 0, 1], // VC:L/VI:L/VA:H/CR:H/IR:H/AR:M
        ],
    ],
    [
        &[],                   // EQ3 = 2 with EQ6 = 0 cannot occur
        &[[1, 1, 1, 0, 0, 0]], // VC:L/VI:L/VA:L/CR:H/IR:H/AR:H
    ],
];

/// EQ4 maxima as (SC, SI, SA), by EQ4 level. SC indexes H, L, N; SI and SA
/// index S, H, L, N.
pub(super) const MAX_EQ4: [[u8; 3]; 3] = [
    [0, 0, 0], // SC:H/SI:S/SA:S
    [0, 1, 1], // SC:H/SI:H/SA:H
    [1, 2, 2], // SC:L/SI:L/SA:L
];

/// `MacroVector` depths (`max_severity.js`), in steps of 0.1.
pub(super) const DEPTH_EQ1: [u8; 3] = [1, 4, 5];
/// See [`DEPTH_EQ1`].
pub(super) const DEPTH_EQ2: [u8; 2] = [1, 2];
/// By EQ3 then EQ6; `None` where the combination cannot occur.
pub(super) const DEPTH_EQ3_EQ6: [[Option<u8>; 2]; 3] =
    [[Some(7), Some(6)], [Some(8), Some(8)], [None, Some(10)]];
/// See [`DEPTH_EQ1`].
pub(super) const DEPTH_EQ4: [u8; 3] = [6, 5, 4];
