// @generated from the pinned sources in data/sources.toml. Do not edit.
// Source: OWASP Top 10 2021 (via MITRE CWE 5.0), OWASP Top 10 2025, OWASP API Security Top 10 2023.
// Identifiers, titles and CWE mappings from the OWASP Foundation; see NOTICE.

use crate::{CweId as W, OwaspCategory, OwaspId as O, OwaspList as L};

pub static TOP10_2021: &[OwaspCategory] = &[
    OwaspCategory { id: O { list: L::Top10_2021, rank: 1 }, name: "Broken Access Control", cwes: &[W(22), W(23), W(35), W(59), W(200), W(201), W(219), W(264), W(275), W(276), W(284), W(285), W(352), W(359), W(377), W(402), W(425), W(441), W(497), W(538), W(540), W(548), W(552), W(566), W(601), W(639), W(651), W(668), W(706), W(862), W(863), W(913), W(922), W(1275)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 2 }, name: "Cryptographic Failures", cwes: &[W(261), W(296), W(310), W(319), W(321), W(322), W(323), W(324), W(325), W(326), W(327), W(328), W(329), W(330), W(331), W(335), W(336), W(337), W(338), W(340), W(347), W(523), W(720), W(757), W(759), W(760), W(780), W(818), W(916)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 3 }, name: "Injection", cwes: &[W(20), W(74), W(75), W(77), W(78), W(79), W(80), W(83), W(87), W(88), W(89), W(90), W(91), W(93), W(94), W(95), W(96), W(97), W(98), W(99), W(113), W(116), W(138), W(184), W(470), W(471), W(564), W(610), W(643), W(644), W(652), W(917)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 4 }, name: "Insecure Design", cwes: &[W(73), W(183), W(209), W(213), W(235), W(256), W(257), W(266), W(269), W(280), W(311), W(312), W(313), W(316), W(419), W(430), W(434), W(444), W(451), W(472), W(501), W(522), W(525), W(539), W(579), W(598), W(602), W(642), W(646), W(650), W(653), W(656), W(657), W(799), W(807), W(840), W(841), W(927), W(1021), W(1173)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 5 }, name: "Security Misconfiguration", cwes: &[W(2), W(11), W(13), W(15), W(16), W(260), W(315), W(520), W(526), W(537), W(541), W(547), W(611), W(614), W(756), W(776), W(942), W(1004), W(1032), W(1174)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 6 }, name: "Vulnerable and Outdated Components", cwes: &[W(937), W(1035), W(1104)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 7 }, name: "Identification and Authentication Failures", cwes: &[W(255), W(259), W(287), W(288), W(290), W(294), W(295), W(297), W(300), W(302), W(304), W(306), W(307), W(346), W(384), W(521), W(613), W(620), W(640), W(798), W(940), W(1216)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 8 }, name: "Software and Data Integrity Failures", cwes: &[W(345), W(353), W(426), W(494), W(502), W(565), W(784), W(829), W(830), W(915)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 9 }, name: "Security Logging and Monitoring Failures", cwes: &[W(117), W(223), W(532), W(778)] },
    OwaspCategory { id: O { list: L::Top10_2021, rank: 10 }, name: "Server-Side Request Forgery (SSRF)", cwes: &[W(918)] },
];

pub static TOP10_2025: &[OwaspCategory] = &[
    OwaspCategory { id: O { list: L::Top10_2025, rank: 1 }, name: "Broken Access Control", cwes: &[W(22), W(23), W(36), W(59), W(61), W(65), W(200), W(201), W(219), W(276), W(281), W(282), W(283), W(284), W(285), W(352), W(359), W(377), W(379), W(402), W(424), W(425), W(441), W(497), W(538), W(540), W(548), W(552), W(566), W(601), W(615), W(639), W(668), W(732), W(749), W(862), W(863), W(918), W(922), W(1275)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 2 }, name: "Security Misconfiguration", cwes: &[W(5), W(11), W(13), W(15), W(16), W(260), W(315), W(489), W(526), W(547), W(611), W(614), W(776), W(942), W(1004), W(1174)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 3 }, name: "Software Supply Chain Failures", cwes: &[W(447), W(1035), W(1104), W(1329), W(1357), W(1395)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 4 }, name: "Cryptographic Failures", cwes: &[W(261), W(296), W(319), W(320), W(321), W(322), W(323), W(324), W(325), W(326), W(327), W(328), W(329), W(330), W(331), W(332), W(334), W(335), W(336), W(337), W(338), W(340), W(342), W(347), W(523), W(757), W(759), W(760), W(780), W(916), W(1240), W(1241)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 5 }, name: "Injection", cwes: &[W(20), W(74), W(76), W(77), W(78), W(79), W(80), W(83), W(86), W(88), W(89), W(90), W(91), W(93), W(94), W(95), W(96), W(97), W(98), W(99), W(103), W(104), W(112), W(113), W(114), W(115), W(116), W(129), W(159), W(470), W(493), W(500), W(564), W(610), W(643), W(644), W(917)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 6 }, name: "Insecure Design", cwes: &[W(73), W(183), W(256), W(266), W(269), W(286), W(311), W(312), W(313), W(316), W(362), W(382), W(419), W(434), W(436), W(444), W(451), W(454), W(472), W(501), W(522), W(525), W(539), W(598), W(602), W(628), W(642), W(646), W(653), W(656), W(657), W(676), W(693), W(799), W(807), W(841), W(1021), W(1022), W(1125)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 7 }, name: "Authentication Failures", cwes: &[W(258), W(259), W(287), W(288), W(289), W(290), W(291), W(293), W(294), W(295), W(297), W(298), W(299), W(300), W(302), W(303), W(304), W(305), W(306), W(307), W(308), W(309), W(346), W(350), W(384), W(521), W(613), W(620), W(640), W(798), W(940), W(941), W(1390), W(1391), W(1392), W(1393)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 8 }, name: "Software or Data Integrity Failures", cwes: &[W(345), W(353), W(426), W(427), W(494), W(502), W(506), W(509), W(565), W(784), W(829), W(830), W(915), W(926)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 9 }, name: "Security Logging & Alerting Failures", cwes: &[W(117), W(221), W(223), W(532), W(778)] },
    OwaspCategory { id: O { list: L::Top10_2025, rank: 10 }, name: "Mishandling of Exceptional Conditions", cwes: &[W(209), W(215), W(234), W(235), W(248), W(252), W(274), W(280), W(369), W(390), W(391), W(394), W(396), W(397), W(460), W(476), W(478), W(484), W(550), W(636), W(703), W(754), W(755), W(756)] },
];

pub static API_2023: &[OwaspCategory] = &[
    OwaspCategory { id: O { list: L::Api2023, rank: 1 }, name: "Broken Object Level Authorization", cwes: &[W(285), W(639)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 2 }, name: "Broken Authentication", cwes: &[W(204), W(307)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 3 }, name: "Broken Object Property Level Authorization", cwes: &[W(213), W(915)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 4 }, name: "Unrestricted Resource Consumption", cwes: &[W(400), W(770), W(799)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 5 }, name: "Broken Function Level Authorization", cwes: &[W(285)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 6 }, name: "Unrestricted Access to Sensitive Business Flows", cwes: &[] },
    OwaspCategory { id: O { list: L::Api2023, rank: 7 }, name: "Server Side Request Forgery", cwes: &[W(918)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 8 }, name: "Security Misconfiguration", cwes: &[W(2), W(16), W(209), W(319), W(388), W(444), W(942)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 9 }, name: "Improper Inventory Management", cwes: &[W(1059)] },
    OwaspCategory { id: O { list: L::Api2023, rank: 10 }, name: "Unsafe Consumption of APIs", cwes: &[W(20), W(200), W(319)] },
];
