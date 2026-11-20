//! Coefficients and predictions checked against scikit-learn 1.9.
//!
//! Both datasets are generated inline from integer arithmetic so Python
//! and Rust build bit-identical inputs:
//!
//! * "diabetes-like": 80 samples, 6 features (one correlated with
//!   another), `y = 150 + Xβ + noise`;
//! * "iris-like": 90 samples, 4 features, 3 overlapping classes.

#![allow(
    clippy::suboptimal_flops,
    clippy::cast_precision_loss,
    clippy::unreadable_literal,
    clippy::excessive_precision,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_const_for_fn,
    clippy::many_single_char_names,
    reason = "reference values and test helpers"
)]

use rune_linear_model::{
    ClassWeight, ClassifierLoss, ElasticNet, LearningRate, LinearError, LinearRegression,
    LogisticRegression, RegressorLoss, Ridge, RidgeSolver, SgdClassifier, SgdPenalty, SgdRegressor,
};
use rune_ml_core::Matrix;

// Values printed by scikit-learn 1.9 for the datasets built below.
const OLS_COEF: [f64; 6] = [
    304.17248159940397,
    -199.78756132114566,
    48.49630155503737,
    0.793598728758409,
    124.0623341754911,
    27.078037124216415,
];
const OLS_INTERCEPT: f64 = 148.60487144899116;
const OLS_W_COEF: [f64; 6] = [
    298.1263005260927,
    -199.6017830977534,
    47.92215385955798,
    -1.0671847280322226,
    124.54572959837171,
    26.208177047506865,
];
const OLS_W_INTERCEPT: f64 = 148.51036425918207;
const OLS_NOI_COEF: [f64; 6] = [
    337.95019906186525,
    -215.48124186180792,
    31.66137717096421,
    -28.329271932800186,
    106.34918343476633,
    -51.878009120939176,
];
const RIDGE1_COEF: [f64; 6] = [
    237.19065011053016,
    -173.63092613915077,
    50.27838372391043,
    -2.5687663970777597,
    104.63600221922225,
    81.97207066939468,
];
const RIDGE1_INTERCEPT: f64 = 148.74378750503564;
const RIDGE10_W_COEF: [f64; 6] = [
    140.56913420125613,
    -104.4166820157106,
    32.691827266366126,
    -13.45838944033402,
    61.99271042438996,
    63.65522789447597,
];
const RIDGE10_W_INTERCEPT: f64 = 148.55855839062934;
const RIDGE_WIDE_COEF: [f64; 6] = [
    11.710313551589792,
    -55.55230997313279,
    90.68325062790217,
    13.264619033666971,
    69.22141210812232,
    5.698500593354675,
];
const RIDGE_WIDE_INTERCEPT: f64 = 53.071753934509495;
const RIDGE_DOC_COEF: [f64; 2] = [0.27142857142857146, 0.27142857142857146];
const RIDGE_DOC_INTERCEPT: f64 = 0.18571428571428572;
const LASSO_1_COEF: [f64; 6] = [
    304.60917026844,
    -186.4344969381846,
    34.96133374167099,
    0.0,
    111.57529936559749,
    0.0,
];
const LASSO_1_INTERCEPT: f64 = 148.42172154951786;
const LASSO_5_COEF: [f64; 6] = [
    251.75663647969802,
    -136.63959315226595,
    0.0,
    0.0,
    59.540231208774976,
    0.0,
];
const LASSO_5_INTERCEPT: f64 = 148.12190937465573;
const LASSO_DEFAULT_COEF: [f64; 6] = [
    304.60914828685884,
    -186.43448230746617,
    34.961328329871186,
    0.0,
    111.57529796440276,
    0.0,
];
const LASSO_DEFAULT_INTERCEPT: f64 = 148.42172161450048;
const LASSO_DEFAULT_N_ITER: usize = 5;
const LASSO_DEFAULT_DUAL_GAP: f64 = 0.000344985460924363;
const ENET_W_COEF: [f64; 6] = [
    93.59388597959341,
    -66.42254004364933,
    20.366367512280057,
    -11.13695000178471,
    38.63543059109485,
    42.72581522890972,
];
const ENET_W_INTERCEPT: f64 = 148.5125545842858;
const ENET_NOI_COEF: [f64; 6] = [
    190.82727197963828,
    -151.01545146682818,
    36.152939173493714,
    -25.202433590265134,
    69.42148373889377,
    66.66097439738937,
];
const LASSO_DOC_COEF: [f64; 2] = [0.85, 0.0];
const LASSO_DOC_INTERCEPT: f64 = 0.15000000000000002;
const LOGM_COEF: [f64; 12] = [
    -0.7793551777267591,
    0.46361905881002236,
    -2.1868857385608704,
    -0.9577696539548347,
    -0.4155554445459592,
    -0.4879931389406784,
    -0.10982540276404157,
    -0.2036333885811585,
    1.1949106222727126,
    0.024374080130655656,
    2.296711141324909,
    1.1614030425359902,
];
const LOGM_INTERCEPT: [f64; 3] = [12.069023781258364, 6.619537035239821, -18.688560816497905];
const LOGM_PROBA: [f64; 9] = [
    0.9658334041878207,
    0.03416651123332794,
    8.4578851356603e-08,
    0.008852669390864638,
    0.9160767982604003,
    0.0750705323487349,
    0.00017014232217611052,
    0.1852073043251554,
    0.8146225533526684,
];
const LOGB_COEF: [f64; 4] = [
    1.4627661000542012,
    0.2957751835394047,
    2.3922556099771652,
    1.2917628710882951,
];
const LOGB_INTERCEPT: f64 = -23.57919832452689;
const LOGB_PROBA: [f64; 3] = [
    0.09282027170710974,
    0.8217676966501187,
    0.026691605108272932,
];
const LOGB_W_COEF: [f64; 4] = [
    0.7357056829024315,
    0.18299464259470097,
    1.2388465993036222,
    0.7475154821626171,
];
const LOGB_W_INTERCEPT: f64 = -12.353289127377277;
const LOGM_BAL_COEF: [f64; 12] = [
    -0.735063858695247,
    0.3024924344443806,
    -1.5429376304781701,
    -0.6713717127921018,
    -0.1401349524626704,
    -0.4018145620226951,
    -0.01804727871211439,
    -0.1396447253297586,
    0.8751988111579142,
    0.09932212757831321,
    1.5609849091902832,
    0.8110164381218601,
];
const LOGM_BAL_INTERCEPT: [f64; 3] = [9.50187591845123, 3.7026868557650605, -13.204562774216338];
const LOGB_L1_COEF: [f64; 4] = [
    1.169905527990602,
    0.0,
    2.781560654386157,
    0.8535318453154217,
];
const LOGB_L1_INTERCEPT: f64 = -22.076017646100603;
const LOGM_EN_COEF: [f64; 12] = [
    -0.08997977943106376,
    0.0,
    -1.5632604342877023,
    -0.23605348589143715,
    0.0,
    -0.14531065447277447,
    0.0,
    0.0,
    0.6287025038651322,
    0.0,
    1.3437274340583918,
    0.5468313347016804,
];
const LOGM_EN_INTERCEPT: [f64; 3] = [7.05274762078317, 2.3022561905321552, -9.355003811311244];
const LOGB_NOPEN_NOI_COEF: [f64; 2] = [0.40381737988396094, -0.8265440016028833];
const LOG_DOC_COEF: f64 = 0.9582654626232315;
const LOG_DOC_INTERCEPT: f64 = -1.4373817253463446;
const SGDR_COEF: [f64; 6] = [
    0.4204518411121432,
    -0.3546526540899356,
    0.14183741438596245,
    -0.01351076148544933,
    0.21137337688690924,
    0.28633621459339004,
];
const SGDR_INTERCEPT: f64 = -0.004981185447316393;
const SGDR_T: f64 = 401.0;
const SGDR_EN_HUBER_COEF: [f64; 6] = [
    0.4735697473897702,
    -0.4730576638588876,
    0.14394445783306783,
    0.0011260812215081496,
    0.26416529261689925,
    0.27839077491838593,
];
const SGDR_EN_HUBER_INTERCEPT: f64 = 0.012992627536070236;
const SGDR_L1_EPS_COEF: [f64; 6] = [
    0.3810999873926196,
    -0.33048310122615576,
    0.10330846491522833,
    0.03048665095294429,
    0.16998527204237673,
    0.24717183939841797,
];
const SGDR_L1_EPS_INTERCEPT: f64 = 0.015460604303318849;
const SGDR_TOL_COEF: [f64; 6] = [
    0.5462612327937909,
    -0.5114110118517754,
    0.173919620880117,
    0.0016969996839906278,
    0.29629580274009804,
    0.2744800364208551,
];
const SGDR_TOL_INTERCEPT: f64 = -0.0007001134827257469;
const SGDR_TOL_N_ITER: usize = 18;
const SGDR_PARTIAL_COEF: [f64; 6] = [
    0.21348155669326377,
    -0.1344879662075425,
    0.0718514422279596,
    -0.013693674679851782,
    0.09502220208937037,
    0.16796407436478003,
];
const SGDR_PARTIAL_INTERCEPT: f64 = -0.011387167487135988;
const SGDR_PARTIAL_T: f64 = 81.0;
const SGDC_HINGE_COEF: [f64; 4] = [
    17.476807707551334,
    7.583435237801424,
    43.753885126980606,
    19.54631803608611,
];
const SGDC_HINGE_INTERCEPT: f64 = -38.79936617149669;
const SGDC_LOG_MULTI_COEF: [f64; 12] = [
    -0.7986547773611414,
    0.7581569925833495,
    -2.3292071527131397,
    -1.2530277633214377,
    -0.5417861556284126,
    -0.9987959444389085,
    0.5916152899489522,
    -0.32535785802461886,
    1.4596763714830199,
    0.20618282910239966,
    2.9066522741797343,
    1.483191451100633,
];
const SGDC_LOG_MULTI_INTERCEPT: [f64; 3] = [
    -2.3775703899641187,
    -0.5725409184959112,
    -3.4438187466889776,
];
const SGDC_LOG_PROBA: [f64; 6] = [
    0.6378281567831158,
    0.36216801954762334,
    3.823669260887877e-06,
    0.011677836205731975,
    0.8879777184443403,
    0.10034444534992777,
];
const SGDC_MH_BAL_COEF: [f64; 12] = [
    -60.78128837810081,
    102.37235172286599,
    -143.7367746622639,
    -125.12407605423876,
    -21.84180249110816,
    -60.29084936944171,
    -70.28519256513783,
    -48.770370685801915,
    27.12473035188043,
    17.025188402944462,
    172.24464123815267,
    48.5742023628564,
];
const SGDC_MH_BAL_INTERCEPT: [f64; 3] =
    [-129.1309195191187, 82.32519454497972, -132.81410594058008];
const SGDC_LOG_L1_COEF: [f64; 4] = [
    0.38888955091125704,
    0.18199612667368636,
    0.2791333496030795,
    0.29988262839291224,
];
const SGDC_LOG_L1_INTERCEPT: f64 = -0.14077724942997794;
const SGDC_TOL_N_ITER: usize = 43;
const SGDC_TOL_COEF: [f64; 12] = [
    -0.09943623233940543,
    7.915638520264997,
    -18.358646673777148,
    -10.432134710043764,
    -3.816187067421065,
    -7.2710932041526055,
    1.0741496520332956,
    -2.3304271177020985,
    19.45778303079787,
    -2.5980732693942064,
    47.3540524640971,
    14.598373206730933,
];
const SGDC_TOL_INTERCEPT: [f64; 3] = [-13.349868430851924, 3.916864735714997, -40.59775660032049];
const SGDC_STREAM_COEF: [f64; 12] = [
    -0.10702476841016717,
    2.144327720117939,
    -8.701594204244962,
    -6.125855607524514,
    -2.3363476568651556,
    -11.512411046622063,
    4.2766351816282775,
    -3.707404850575986,
    14.82521312139996,
    -3.0899504621076455,
    34.968857388420645,
    14.990695619560856,
];
const SGDC_STREAM_INTERCEPT: [f64; 3] = [-9.239584006760415, 7.898754312826508, -39.43338173404313];
const SGDC_PERC_ADAPT_N_ITER: usize = 20;
const SGDC_PERC_ADAPT_COEF: [f64; 4] = [
    0.1563178589821018,
    -0.03828508870207046,
    0.621341131186407,
    0.16940711862299934,
];
const SGDC_PERC_ADAPT_INTERCEPT: f64 = -0.6;

fn diabetes() -> (Matrix<f64>, Vec<f64>) {
    let (n, p) = (80_usize, 6_usize);
    let beta = [300.0, -200.0, 50.0, 0.0, 120.0, 30.0];
    let mut x = Matrix::zeros(n, p).unwrap();
    let mut y = Vec::with_capacity(n);
    for i in 0..n {
        for j in 0..5 {
            x[(i, j)] = ((i * (j + 3) * 37 + j * 11) % 101) as f64 / 101.0 - 0.5;
        }
        x[(i, 5)] = 0.5 * x[(i, 0)] + 0.3 * (((i * 53) % 29) as f64 / 29.0 - 0.5);
        let noise = (((i * 31) % 23) as f64 / 23.0 - 0.5) * 40.0;
        let lin: f64 = x.row(i).iter().zip(&beta).map(|(a, b)| a * b).sum();
        y.push(150.0 + lin + noise);
    }
    (x, y)
}

fn diabetes_weights() -> Vec<f64> {
    (0..80).map(|i| 1.0 + (i % 4) as f64 * 0.5).collect()
}

fn iris() -> (Matrix<f64>, Vec<usize>) {
    let centers = [
        [5.0, 3.4, 1.5, 0.25],
        [5.9, 2.8, 4.3, 1.3],
        [6.6, 3.0, 5.5, 2.0],
    ];
    let mut rows = Vec::new();
    let mut y = Vec::new();
    for i in 0..90_usize {
        let c = i % 3;
        let row: Vec<f64> = (0..4)
            .map(|j| {
                let k = (i * (j + 2) * 17 + c * 5 + j * 7) % 19;
                centers[c][j] + (k as f64 / 19.0 - 0.5) * 1.6
            })
            .collect();
        rows.push(row);
        y.push(c);
    }
    (Matrix::from_rows(&rows).unwrap(), y)
}

/// Rows of `x` (and labels) where `keep` holds.
fn subset(
    x: &Matrix<f64>,
    y: &[usize],
    keep: impl Fn(usize, usize) -> bool,
) -> (Matrix<f64>, Vec<usize>) {
    let idx: Vec<usize> = (0..y.len()).filter(|&i| keep(i, y[i])).collect();
    (
        x.select_rows(&idx).unwrap(),
        idx.iter().map(|&i| y[i]).collect(),
    )
}

/// Column-wise `(x − mean) / std` with the population std, like sklearn's
/// `StandardScaler`.
fn standardize(x: &Matrix<f64>) -> Matrix<f64> {
    let (n, p) = x.shape();
    let mean = x.column_means();
    let mut out = x.clone();
    for j in 0..p {
        let var = x.column(j).map(|v| (v - mean[j]).powi(2)).sum::<f64>() / n as f64;
        let sd = var.sqrt();
        for i in 0..n {
            out[(i, j)] = (x[(i, j)] - mean[j]) / sd;
        }
    }
    out
}

fn standardize_target(y: &[f64]) -> Vec<f64> {
    let n = y.len() as f64;
    let m = y.iter().sum::<f64>() / n;
    let sd = (y.iter().map(|v| (v - m).powi(2)).sum::<f64>() / n).sqrt();
    y.iter().map(|v| (v - m) / sd).collect()
}

#[track_caller]
fn close(got: &[f64], want: &[f64], tol: f64) {
    assert_eq!(got.len(), want.len());
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        let err = (g - w).abs() / w.abs().max(1.0);
        assert!(
            err <= tol,
            "index {i}: got {g}, want {w} (rel err {err:e})\n got {got:?}"
        );
    }
}

#[track_caller]
fn close1(got: f64, want: f64, tol: f64) {
    close(&[got], &[want], tol);
}

// ---------------------------------------------------------------- OLS / ridge

#[test]
fn ols_matches_sklearn() {
    let (x, y) = diabetes();
    let m = LinearRegression::new().fit(x.view(), &y).unwrap();
    close(m.coef(), &OLS_COEF, 1e-10);
    close1(m.intercept(), OLS_INTERCEPT, 1e-10);

    let sw = diabetes_weights();
    let m = LinearRegression::new()
        .fit_weighted(x.view(), &y, Some(&sw))
        .unwrap();
    close(m.coef(), &OLS_W_COEF, 1e-10);
    close1(m.intercept(), OLS_W_INTERCEPT, 1e-10);

    let m = LinearRegression::new()
        .with_fit_intercept(false)
        .fit(x.view(), &y)
        .unwrap();
    close(m.coef(), &OLS_NOI_COEF, 1e-10);
    assert_eq!(m.intercept(), 0.0);
}

#[test]
fn ols_in_f32() {
    let (x, y) = diabetes();
    let x32: Matrix<f32> = x.cast();
    let y32: Vec<f32> = y.iter().map(|&v| v as f32).collect();
    let m = LinearRegression::new().fit(x32.view(), &y32).unwrap();
    let coef: Vec<f64> = m.coef().iter().map(|&v| f64::from(v)).collect();
    close(&coef, &OLS_COEF, 1e-3);
}

#[test]
fn ols_rejects_singular_systems() {
    let (x, y) = diabetes();
    // Duplicate a column: exactly collinear.
    let rows: Vec<Vec<f64>> = x.rows().map(|r| vec![r[0], r[1], r[0]]).collect();
    let xd = Matrix::from_rows(&rows).unwrap();
    assert_eq!(
        LinearRegression::new().fit(xd.view(), &y),
        Err(LinearError::Singular)
    );
    // Constant feature with an intercept.
    let rows: Vec<Vec<f64>> = x.rows().map(|r| vec![r[0], 2.0]).collect();
    let xc = Matrix::from_rows(&rows).unwrap();
    assert_eq!(
        LinearRegression::new().fit(xc.view(), &y),
        Err(LinearError::Singular)
    );
    // Fewer samples than features.
    let few = x.select_rows(&[0, 1, 2]).unwrap();
    assert_eq!(
        LinearRegression::new().fit(few.view(), &y[..3]),
        Err(LinearError::Singular)
    );
    // Ridge with alpha = 0 is OLS and fails the same way; alpha > 0 fixes it.
    assert_eq!(
        Ridge::new(0.0).fit(xd.view(), &y),
        Err(LinearError::Singular)
    );
    let m = Ridge::new(1e-3).fit(xd.view(), &y).unwrap();
    assert!((m.coef()[0] - m.coef()[2]).abs() < 1e-9);
}

#[test]
fn ridge_matches_sklearn() {
    let (x, y) = diabetes();
    let m = Ridge::new(1.0).fit(x.view(), &y).unwrap();
    close(m.coef(), &RIDGE1_COEF, 1e-10);
    close1(m.intercept(), RIDGE1_INTERCEPT, 1e-10);
    // The dual solver gives the same answer.
    let d = Ridge::new(1.0)
        .with_solver(RidgeSolver::Dual)
        .fit(x.view(), &y)
        .unwrap();
    close(d.coef(), &RIDGE1_COEF, 1e-8);

    let sw = diabetes_weights();
    let m = Ridge::new(10.0)
        .fit_weighted(x.view(), &y, Some(&sw))
        .unwrap();
    close(m.coef(), &RIDGE10_W_COEF, 1e-10);
    close1(m.intercept(), RIDGE10_W_INTERCEPT, 1e-10);
}

#[test]
fn ridge_wide_uses_dual() {
    let (x, y) = diabetes();
    let x5 = x.select_rows(&[0, 1, 2, 3, 4]).unwrap();
    let m = Ridge::new(0.5).fit(x5.view(), &y[..5]).unwrap();
    close(m.coef(), &RIDGE_WIDE_COEF, 1e-9);
    close1(m.intercept(), RIDGE_WIDE_INTERCEPT, 1e-9);
    let p = Ridge::new(0.5)
        .with_solver(RidgeSolver::Primal)
        .fit(x5.view(), &y[..5])
        .unwrap();
    close(p.coef(), &RIDGE_WIDE_COEF, 1e-7);
}

#[test]
fn ridge_doc_example() {
    let x = Matrix::from_rows(&[[0.0, 0.0], [0.0, 0.0], [1.0, 1.0]]).unwrap();
    let m = Ridge::new(1.0).fit(x.view(), &[0.0, 0.1, 1.0]).unwrap();
    close(m.coef(), &RIDGE_DOC_COEF, 1e-12);
    close1(m.intercept(), RIDGE_DOC_INTERCEPT, 1e-12);
}

// ---------------------------------------------------------- lasso / enet

#[test]
fn lasso_matches_sklearn() {
    let (x, y) = diabetes();
    for (alpha, coef, icpt) in [
        (1.0, LASSO_1_COEF, LASSO_1_INTERCEPT),
        (5.0, LASSO_5_COEF, LASSO_5_INTERCEPT),
    ] {
        let m = ElasticNet::lasso(alpha)
            .with_tol(1e-12)
            .with_max_iter(100_000)
            .fit(x.view(), &y)
            .unwrap();
        assert!(m.converged());
        close(m.coef(), &coef, 1e-8);
        close1(m.intercept(), icpt, 1e-8);
        // Exact zeros where sklearn has them.
        for (g, w) in m.coef().iter().zip(&coef) {
            assert_eq!(*g == 0.0, *w == 0.0);
        }
    }
}

#[test]
fn lasso_default_tolerance_follows_sklearn_path() {
    let (x, y) = diabetes();
    let m = ElasticNet::lasso(1.0).fit(x.view(), &y).unwrap();
    assert!(m.converged());
    assert_eq!(m.n_iter(), LASSO_DEFAULT_N_ITER);
    close(m.coef(), &LASSO_DEFAULT_COEF, 1e-9);
    close1(m.intercept(), LASSO_DEFAULT_INTERCEPT, 1e-9);
    close1(m.dual_gap(), LASSO_DEFAULT_DUAL_GAP, 1e-6);
    assert_eq!(m.support(), vec![0, 1, 2, 4]);
}

#[test]
fn elastic_net_matches_sklearn() {
    let (x, y) = diabetes();
    let sw = diabetes_weights();
    let m = ElasticNet::new(0.5, 0.7)
        .with_tol(1e-12)
        .with_max_iter(100_000)
        .fit_weighted(x.view(), &y, Some(&sw))
        .unwrap();
    close(m.coef(), &ENET_W_COEF, 1e-8);
    close1(m.intercept(), ENET_W_INTERCEPT, 1e-8);

    let m = ElasticNet::new(0.05, 0.3)
        .with_fit_intercept(false)
        .with_tol(1e-12)
        .with_max_iter(100_000)
        .fit(x.view(), &y)
        .unwrap();
    close(m.coef(), &ENET_NOI_COEF, 1e-8);
}

#[test]
fn lasso_doc_example() {
    let x = Matrix::from_rows(&[[0.0, 0.0], [1.0, 1.0], [2.0, 2.0]]).unwrap();
    let m = ElasticNet::lasso(0.1)
        .fit(x.view(), &[0.0, 1.0, 2.0])
        .unwrap();
    close(m.coef(), &LASSO_DOC_COEF, 1e-12);
    close1(m.intercept(), LASSO_DOC_INTERCEPT, 1e-12);
}

#[test]
fn warm_start_and_random_selection_reach_the_same_optimum() {
    let (x, y) = diabetes();
    let est = ElasticNet::lasso(1.0)
        .with_tol(1e-12)
        .with_max_iter(100_000);
    let cold = est.fit(x.view(), &y).unwrap();
    let start = ElasticNet::lasso(5.0).fit(x.view(), &y).unwrap();
    let warm = est.fit_warm(x.view(), &y, None, &start).unwrap();
    close(warm.coef(), &LASSO_1_COEF, 1e-8);
    assert!(warm.n_iter() <= cold.n_iter());
    let random = est
        .with_selection(rune_linear_model::Selection::Random)
        .with_seed(7)
        .fit(x.view(), &y)
        .unwrap();
    close(random.coef(), &LASSO_1_COEF, 1e-7);
}

#[test]
fn max_iter_reports_non_convergence() {
    let (x, y) = diabetes();
    let m = ElasticNet::new(0.01, 0.5)
        .with_tol(1e-14)
        .with_max_iter(2)
        .fit(x.view(), &y)
        .unwrap();
    assert!(!m.converged());
    assert_eq!(m.n_iter(), 2);
}

// ------------------------------------------------------------- logistic

fn rows(m: &Matrix<f64>) -> Vec<f64> {
    m.as_slice().to_vec()
}

#[test]
fn logistic_multinomial_matches_sklearn() {
    let (x, y) = iris();
    let m = LogisticRegression::new()
        .with_tol(1e-10)
        .with_max_iter(10_000)
        .fit(x.view(), &y)
        .unwrap();
    assert!(m.converged());
    assert_eq!(m.classes(), &[0, 1, 2]);
    close(&rows(m.coef()), &LOGM_COEF, 1e-5);
    close(m.intercept(), &LOGM_INTERCEPT, 1e-5);
    let first = x.select_rows(&[0, 1, 2]).unwrap();
    let proba = m.predict_proba(first.view()).unwrap();
    close(proba.as_slice(), &LOGM_PROBA, 1e-6);
    assert!(m.score(x.view(), &y).unwrap() > 0.85);
}

#[test]
fn logistic_binary_matches_sklearn() {
    let (x, y) = iris();
    let (xb, yb) = subset(&x, &y, |_, c| c > 0);
    let m = LogisticRegression::new()
        .with_tol(1e-10)
        .with_max_iter(10_000)
        .fit(xb.view(), &yb)
        .unwrap();
    assert_eq!(m.coef().shape(), (1, 4));
    close(&rows(m.coef()), &LOGB_COEF, 1e-6);
    close1(m.intercept()[0], LOGB_INTERCEPT, 1e-6);
    let first = xb.select_rows(&[0, 1, 2]).unwrap();
    let proba = m.predict_proba(first.view()).unwrap();
    let p1: Vec<f64> = proba.rows().map(|r| r[1]).collect();
    close(&p1, &LOGB_PROBA, 1e-6);
    for r in proba.rows() {
        assert!((r[0] + r[1] - 1.0).abs() < 1e-12);
    }
    let d = m.decision_function(first.view()).unwrap();
    assert_eq!(d.shape(), (3, 1));

    let sw: Vec<f64> = (0..yb.len()).map(|i| 1.0 + (i % 3) as f64).collect();
    let m = LogisticRegression::new()
        .with_c(0.1)
        .with_tol(1e-10)
        .with_max_iter(10_000)
        .fit_weighted(xb.view(), &yb, Some(&sw))
        .unwrap();
    close(&rows(m.coef()), &LOGB_W_COEF, 1e-6);
    close1(m.intercept()[0], LOGB_W_INTERCEPT, 1e-6);
}

#[test]
fn logistic_balanced_class_weight_matches_sklearn() {
    let (x, y) = iris();
    let (xi, yi) = subset(&x, &y, |i, c| c != 0 || i < 12);
    let m = LogisticRegression::new()
        .with_c(0.5)
        .with_class_weight(ClassWeight::Balanced)
        .with_tol(1e-10)
        .with_max_iter(10_000)
        .fit(xi.view(), &yi)
        .unwrap();
    close(&rows(m.coef()), &LOGM_BAL_COEF, 1e-6);
    close(m.intercept(), &LOGM_BAL_INTERCEPT, 1e-6);
}

#[test]
fn logistic_l1_and_elastic_net_match_saga() {
    let (x, y) = iris();
    let (xb, yb) = subset(&x, &y, |_, c| c > 0);
    let m = LogisticRegression::new()
        .with_c(0.5)
        .with_l1_ratio(1.0)
        .with_tol(1e-9)
        .with_max_iter(200_000)
        .fit(xb.view(), &yb)
        .unwrap();
    assert!(m.converged());
    close(&rows(m.coef()), &LOGB_L1_COEF, 1e-5);
    close1(m.intercept()[0], LOGB_L1_INTERCEPT, 1e-5);
    assert_eq!(m.coef()[(0, 1)], 0.0);

    let m = LogisticRegression::new()
        .with_c(0.2)
        .with_l1_ratio(0.5)
        .with_tol(1e-9)
        .with_max_iter(200_000)
        .fit(x.view(), &y)
        .unwrap();
    assert!(m.converged());
    close(&rows(m.coef()), &LOGM_EN_COEF, 1e-5);
    close(m.intercept(), &LOGM_EN_INTERCEPT, 1e-5);
    for (g, w) in m.coef().as_slice().iter().zip(&LOGM_EN_COEF) {
        assert_eq!(*g == 0.0, *w == 0.0);
    }
}

#[test]
fn logistic_without_penalty_or_intercept() {
    let (x, y) = iris();
    let (xb, yb) = subset(&x, &y, |_, c| c > 0);
    let x2 = Matrix::from_rows(&xb.rows().map(|r| [r[0], r[1]]).collect::<Vec<_>>()).unwrap();
    let m = LogisticRegression::new()
        .with_c(f64::INFINITY)
        .with_fit_intercept(false)
        .with_tol(1e-10)
        .with_max_iter(10_000)
        .fit(x2.view(), &yb)
        .unwrap();
    close(&rows(m.coef()), &LOGB_NOPEN_NOI_COEF, 1e-6);
    assert_eq!(m.intercept(), &[0.0]);
}

#[test]
fn logistic_doc_example_and_labels() {
    let x = Matrix::from_rows(&[[0.0], [1.0], [2.0], [3.0]]).unwrap();
    let m = LogisticRegression::new()
        .with_tol(1e-10)
        .fit(x.view(), &["a", "a", "b", "b"])
        .unwrap();
    // The reference used sklearn's default tol = 1e-4.
    close1(m.coef()[(0, 0)], LOG_DOC_COEF, 1e-4);
    close1(m.intercept()[0], LOG_DOC_INTERCEPT, 1e-4);
    assert_eq!(m.predict(x.view()).unwrap(), ["a", "a", "b", "b"]);
}

#[test]
fn logistic_max_iter_reports_non_convergence() {
    let (x, y) = iris();
    let m = LogisticRegression::new()
        .with_max_iter(2)
        .fit(x.view(), &y)
        .unwrap();
    assert!(!m.converged());
    assert_eq!(m.n_iter(), 2);
}

// ------------------------------------------------------------------ SGD

fn sgd_data() -> (Matrix<f64>, Vec<f64>) {
    let (x, y) = diabetes();
    (standardize(&x), standardize_target(&y))
}

fn unshuffled_regressor() -> SgdRegressor {
    SgdRegressor::new().with_shuffle(false)
}

#[test]
fn sgd_regressor_matches_sklearn_step_for_step() {
    let (x, y) = sgd_data();
    let m = unshuffled_regressor()
        .with_tol(None)
        .with_max_iter(5)
        .fit(x.view(), &y)
        .unwrap();
    close(m.coef(), &SGDR_COEF, 1e-9);
    close1(m.intercept(), SGDR_INTERCEPT, 1e-9);
    assert_eq!(m.t(), SGDR_T);
    assert!(m.converged());

    let sw = diabetes_weights();
    let m = unshuffled_regressor()
        .with_tol(None)
        .with_max_iter(4)
        .with_penalty(SgdPenalty::ElasticNet)
        .with_l1_ratio(0.5)
        .with_alpha(0.01)
        .with_loss(RegressorLoss::Huber)
        .with_learning_rate(LearningRate::Constant)
        .with_eta0(0.02)
        .fit_weighted(x.view(), &y, Some(&sw))
        .unwrap();
    close(m.coef(), &SGDR_EN_HUBER_COEF, 1e-9);
    close1(m.intercept(), SGDR_EN_HUBER_INTERCEPT, 1e-9);

    let m = unshuffled_regressor()
        .with_tol(None)
        .with_max_iter(3)
        .with_penalty(SgdPenalty::L1)
        .with_alpha(0.05)
        .with_loss(RegressorLoss::EpsilonInsensitive)
        .fit(x.view(), &y)
        .unwrap();
    close(m.coef(), &SGDR_L1_EPS_COEF, 1e-9);
    close1(m.intercept(), SGDR_L1_EPS_INTERCEPT, 1e-9);
}

#[test]
fn sgd_regressor_stopping_rule_matches_sklearn() {
    let (x, y) = sgd_data();
    let m = unshuffled_regressor().fit(x.view(), &y).unwrap();
    assert_eq!(m.n_iter(), SGDR_TOL_N_ITER);
    assert!(m.converged());
    close(m.coef(), &SGDR_TOL_COEF, 1e-9);
    close1(m.intercept(), SGDR_TOL_INTERCEPT, 1e-9);
}

#[test]
fn sgd_regressor_partial_fit_matches_sklearn() {
    let (x, y) = sgd_data();
    let a = x.select_rows(&(0..40).collect::<Vec<_>>()).unwrap();
    let b = x.select_rows(&(40..80).collect::<Vec<_>>()).unwrap();
    let est = unshuffled_regressor().with_tol(None);
    let mut m = est.partial_fit(a.view(), &y[..40], None).unwrap();
    m.partial_fit(b.view(), &y[40..], None).unwrap();
    close(m.coef(), &SGDR_PARTIAL_COEF, 1e-9);
    close1(m.intercept(), SGDR_PARTIAL_INTERCEPT, 1e-9);
    assert_eq!(m.t(), SGDR_PARTIAL_T);
    assert_eq!(
        m.partial_fit(x.select_rows(&[0]).unwrap().view(), &[1.0, 2.0], None),
        Err(LinearError::LengthMismatch {
            expected: 1,
            found: 2
        })
    );
}

fn unshuffled_classifier() -> SgdClassifier {
    SgdClassifier::new().with_shuffle(false)
}

#[test]
fn sgd_classifier_matches_sklearn_step_for_step() {
    let (x, y) = iris();
    let xs = standardize(&x);
    let (xb, yb) = subset(&xs, &y, |_, c| c > 0);

    let m = unshuffled_classifier()
        .with_tol(None)
        .with_max_iter(5)
        .fit(xb.view(), &yb)
        .unwrap();
    close(&rows(m.coef()), &SGDC_HINGE_COEF, 1e-9);
    close1(m.intercept()[0], SGDC_HINGE_INTERCEPT, 1e-9);

    let m = unshuffled_classifier()
        .with_tol(None)
        .with_max_iter(5)
        .with_loss(ClassifierLoss::LogLoss)
        .with_alpha(0.01)
        .fit(xs.view(), &y)
        .unwrap();
    close(&rows(m.coef()), &SGDC_LOG_MULTI_COEF, 1e-9);
    close(m.intercept(), &SGDC_LOG_MULTI_INTERCEPT, 1e-9);
    let proba = m
        .predict_proba(xs.select_rows(&[0, 1]).unwrap().view())
        .unwrap();
    close(proba.as_slice(), &SGDC_LOG_PROBA, 1e-9);

    let (xi, yi) = subset(&xs, &y, |i, c| c != 0 || i < 12);
    let m = unshuffled_classifier()
        .with_tol(None)
        .with_max_iter(4)
        .with_loss(ClassifierLoss::ModifiedHuber)
        .with_class_weight(ClassWeight::Balanced)
        .fit(xi.view(), &yi)
        .unwrap();
    close(&rows(m.coef()), &SGDC_MH_BAL_COEF, 1e-9);
    close(m.intercept(), &SGDC_MH_BAL_INTERCEPT, 1e-9);

    let m = unshuffled_classifier()
        .with_tol(None)
        .with_max_iter(3)
        .with_loss(ClassifierLoss::LogLoss)
        .with_penalty(SgdPenalty::L1)
        .with_alpha(0.01)
        .with_learning_rate(LearningRate::InvScaling)
        .with_eta0(0.1)
        .fit(xb.view(), &yb)
        .unwrap();
    close(&rows(m.coef()), &SGDC_LOG_L1_COEF, 1e-9);
    close1(m.intercept()[0], SGDC_LOG_L1_INTERCEPT, 1e-9);
}

#[test]
fn sgd_classifier_stopping_rules_match_sklearn() {
    let (x, y) = iris();
    let xs = standardize(&x);
    let m = unshuffled_classifier().fit(xs.view(), &y).unwrap();
    assert_eq!(m.n_iter(), SGDC_TOL_N_ITER);
    close(&rows(m.coef()), &SGDC_TOL_COEF, 1e-9);
    close(m.intercept(), &SGDC_TOL_INTERCEPT, 1e-9);

    let (xb, yb) = subset(&xs, &y, |_, c| c > 0);
    let m = unshuffled_classifier()
        .with_loss(ClassifierLoss::Perceptron)
        .with_penalty(SgdPenalty::None)
        .with_learning_rate(LearningRate::Adaptive)
        .with_eta0(0.1)
        .with_max_iter(20)
        .fit(xb.view(), &yb)
        .unwrap();
    assert_eq!(m.n_iter(), SGDC_PERC_ADAPT_N_ITER);
    assert!(!m.converged());
    close(&rows(m.coef()), &SGDC_PERC_ADAPT_COEF, 1e-9);
    close1(m.intercept()[0], SGDC_PERC_ADAPT_INTERCEPT, 1e-9);
}

#[test]
fn sgd_shuffled_runs_are_deterministic_and_accurate() {
    let (x, y) = iris();
    let xs = standardize(&x);
    let est = SgdClassifier::new()
        .with_loss(ClassifierLoss::LogLoss)
        .with_seed(42);
    let a = est.fit(xs.view(), &y).unwrap();
    let b = est.fit(xs.view(), &y).unwrap();
    assert_eq!(a, b);
    assert!(a.score(xs.view(), &y).unwrap() > 0.8);
    let c = est.with_seed(43).fit(xs.view(), &y).unwrap();
    assert_ne!(a.coef(), c.coef());

    let (xd, yd) = sgd_data();
    let r = SgdRegressor::new()
        .with_seed(1)
        .fit(xd.view(), &yd)
        .unwrap();
    assert!(r.score(xd.view(), &yd).unwrap() > 0.85);
}

#[test]
fn sgd_classifier_partial_fit_streams_batches() {
    let (x, y) = iris();
    let xs = standardize(&x);
    let est = unshuffled_classifier().with_loss(ClassifierLoss::LogLoss);
    let first: Vec<usize> = (0..45).collect();
    let mut m = est
        .partial_fit(
            xs.select_rows(&first).unwrap().view(),
            &y[..45],
            &[0, 1, 2],
            None,
        )
        .unwrap();
    for _ in 0..20 {
        for chunk in (0..90).collect::<Vec<_>>().chunks(30) {
            let xb = xs.select_rows(chunk).unwrap();
            let yb: Vec<usize> = chunk.iter().map(|&i| y[i]).collect();
            m.partial_fit(xb.view(), &yb, None).unwrap();
        }
    }
    assert!(m.score(xs.view(), &y).unwrap() > 0.8);
    assert_eq!(m.t(), 1.0 + 45.0 + 20.0 * 90.0);
    close(&rows(m.coef()), &SGDC_STREAM_COEF, 1e-9);
    close(m.intercept(), &SGDC_STREAM_INTERCEPT, 1e-9);
    assert_eq!(
        m.partial_fit(xs.select_rows(&[0]).unwrap().view(), &[7], None),
        Err(LinearError::UnknownLabel { index: 0 })
    );
    assert!(
        est.with_class_weight(ClassWeight::Balanced)
            .partial_fit(xs.view(), &y, &[0, 1, 2], None)
            .is_err()
    );
}
