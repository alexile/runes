//! Known-answer tests from FIRST's example documents.
//!
//! - <https://www.first.org/cvss/v3.1/examples> and
//!   <https://www.first.org/cvss/v3.0/examples>: every scored example, with
//!   the base score the document states (each also matches FIRST's
//!   calculator).
//! - <https://www.first.org/cvss/v4.0/examples>: every distinct vector, with
//!   the score of FIRST's v4.0 calculator (first.org/cvss/calculator/4.0).
//!   For five vectors the document's text states a different score, noted
//!   inline: the document predates the final `MacroVector` table, while the
//!   calculator's code and table are the reference implementation. Two
//!   vectors are listed out of order in the document, which the
//!   specification forbids; they appear here in canonical order.

use rune_cvss::{Score, Vector, Vector3, Vector4, Version};

const V3_1_EXAMPLES: &[(&str, &str, &str)] = &[
    (
        "MySQL Stored SQL Injection (CVE-2013-0375)",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "6.4",
    ),
    (
        "SSLv3 POODLE Vulnerability (CVE-2014-3566)",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "3.1",
    ),
    (
        "VMware Guest to Host Escape Vulnerability (CVE-2012-1516)",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "9.9",
    ),
    (
        "Apache Tomcat XML Parser Vulnerability (CVE-2009-0783)",
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L",
        "4.2",
    ),
    (
        "Cisco IOS Arbitrary Command Execution Vulnerability (CVE-2012-0384)",
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "7.2",
    ),
    (
        "Apple iWork Denial of Service Vulnerability (CVE-2015-1098)",
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "7.8",
    ),
    (
        "OpenSSL Heartbleed Vulnerability (CVE-2014-0160)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "7.5",
    ),
    (
        "GNU Bourne-Again Shell (Bash) ‘Shellshock’ Vulnerability (CVE-2014-6271)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "9.8",
    ),
    (
        "DNS Kaminsky Bug (CVE-2008-1447)",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",
        "6.8",
    ),
    (
        "Sophos Login Screen Bypass Vulnerability (CVE-2014-2005)",
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "6.8",
    ),
    (
        "Joomla Directory Traversal Vulnerability (CVE-2010-0467)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
        "5.8",
    ),
    (
        "Cisco Access Control Bypass Vulnerability (CVE-2012-1342)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N",
        "5.8",
    ),
    (
        "Juniper Proxy ARP Denial of Service Vulnerability (CVE-2013-6014)",
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H",
        "9.3",
    ),
    (
        "Cantemo Portal Stored Cross-site Scripting Vulnerability (CVE-2019-7551)",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
        "9.0",
    ),
    (
        "Adobe Acrobat Buffer Overflow Vulnerability (CVE-2009-0658)",
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "7.8",
    ),
    (
        "Microsoft Windows Bluetooth Remote Code Execution Vulnerability (CVE-2011-1265)",
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "8.8",
    ),
    (
        "Apple iOS Security Control Bypass Vulnerability (CVE-2014-2019)",
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "4.6",
    ),
    (
        "SearchBlox Cross-Site Request Forgery Vulnerability (CVE-2015-0970)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "8.8",
    ),
    (
        "SSL/TLS MITM Vulnerability (CVE-2014-0224)",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "7.4",
    ),
    (
        "Google Chrome Sandbox Bypass vulnerability (CVE-2012-5376)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "9.6",
    ),
    (
        "Google Chrome PDFium JPEG 2000 Remote Code Execution Vulnerability (CVE-2016-1645)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "8.8",
    ),
    (
        "SAMR/LSAD Privilege Escalation via Protocol Downgrade Vulnerability (“Badlock”) (CVE-2016-0128 and CVE-2016-2118)",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "6.8",
    ),
    (
        "WordPress Mail Plugin Reflected Cross-site Scripting Vulnerability (CVE-2017-5942)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "6.1",
    ),
    (
        "Opera DLL search order hijacking (CVE-2018-18913)",
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "7.8",
    ),
    (
        "Remote Code Execution in Oracle Outside in Technology (CVE-2016-5558)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
        "8.6",
    ),
    (
        "Lenovo ThnkPwn Exploit (CVE-2016-5729)",
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "8.2",
    ),
    (
        "Failure to Lock Flash on Resume from sleep (CVE-2015-2890)",
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H",
        "6.0",
    ),
    (
        "Intel DCI Issue (CVE-2018-3652)",
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "7.6",
    ),
];

const V3_0_EXAMPLES: &[(&str, &str, &str)] = &[
    (
        "phpMyAdmin Reflected Cross-site Scripting Vulnerability (CVE-2013-1937)",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "6.1",
    ),
    (
        "MySQL Stored SQL Injection (CVE-2013-0375)",
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "6.4",
    ),
    (
        "SSLv3 POODLE Vulnerability (CVE-2014-3566)",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "3.1",
    ),
    (
        "VMware Guest to Host Escape Vulnerability (CVE-2012-1516)",
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "9.9",
    ),
    (
        "Apache Tomcat XML Parser Vulnerability (CVE-2009-0783)",
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L",
        "4.2",
    ),
    (
        "Cisco IOS Arbitrary Command Execution Vulnerability (CVE-2012-0384)",
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "8.8",
    ),
    (
        "Apple iWork Denial of Service Vulnerability (CVE-2015-1098)",
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "7.8",
    ),
    (
        "OpenSSL Heartbleed Vulnerability (CVE-2014-0160)",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "7.5",
    ),
    (
        "GNU Bourne-Again Shell (Bash) 'Shellshock' Vulnerability (CVE-2014-6271)",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "9.8",
    ),
    (
        "DNS Kaminsky Bug (CVE-2008-1447)",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",
        "6.8",
    ),
    (
        "Sophos Login Screen Bypass Vulnerability (CVE-2014-2005)",
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "6.8",
    ),
    (
        "Joomla Directory Traversal Vulnerability (CVE-2010-0467)",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
        "5.8",
    ),
    (
        "Cisco Access Control Bypass Vulnerability (CVE-2012-1342)",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N",
        "5.8",
    ),
    (
        "Juniper Proxy ARP Denial of Service Vulnerability (CVE-2013-6014)",
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H",
        "9.3",
    ),
    (
        "DokuWiki Reflected Cross-site Scripting Attack (CVE-2014-9253)",
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "5.4",
    ),
    (
        "Adobe Acrobat Buffer Overflow Vulnerability (CVE-2009-0658)",
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "7.8",
    ),
    (
        "Microsoft Windows Bluetooth Remote Code Execution Vulnerability (CVE-2011-1265)",
        "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "8.8",
    ),
    (
        "Apple iOS Security Control Bypass Vulnerability (CVE-2014-2019)",
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "4.6",
    ),
    (
        "SearchBlox Cross-Site Request Forgery Vulnerability (CVE-2015-0970)",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "8.8",
    ),
    (
        "SSL/TLS MITM Vulnerability (CVE-2014-0224)",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "7.4",
    ),
    (
        "Google Chrome Sandbox Bypass vulnerability (CVE-2012-5376)",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "9.6",
    ),
    (
        "SAMR/LSAD Privilege Escalation via Protocol Downgrade Vulnerability (“Badlock”) (CVE-2016-0128 and CVE-2016-2118)",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "6.8",
    ),
];

const V4_0_EXAMPLES: &[(&str, &str)] = &[
    (
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "7.3",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "7.7",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
        "5.2",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
        "8.3",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
        "8.1",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "4.6",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
        "5.1",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
        "6.9",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
        "5.9",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "9.4",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H",
        "9.3",
    ), // the document states 9.4
    (
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D",
        "8.3",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
        "8.6",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A",
        "8.7",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
        "9.3",
    ),
    (
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "9.2",
    ),
    (
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L",
        "5.5",
    ),
    (
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H",
        "6.4",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I",
        "8.4",
    ), // the document states 9.3
    (
        "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I",
        "7.1",
    ), // the document states 8.7
    (
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "7.0",
    ), // the document states 8.6
    (
        "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P",
        "8.2",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "7.1",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "8.2",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L",
        "8.7",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U",
        "6.6",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U/MVA:H/MSA:N",
        "6.6",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
        "5.1",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
        "5.1",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N",
        "8.5",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        "5.1",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "7.7",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "8.3",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U",
        "5.6",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "8.5",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/MUI:A",
        "5.7",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
        "9.2",
    ),
    (
        "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "5.4",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "8.7",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "6.9",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "9.3",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N",
        "6.9",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N/E:U/CR:L/IR:L/AR:L",
        "2.7",
    ), // the document states 6.9
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H",
        "7.8",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L",
        "6.9",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L/MSI:N/MSA:N",
        "6.9",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P",
        "8.5",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L",
        "9.4",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:L/IR:H/AR:L/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:L/MSC:N/MSI:S/MSA:L",
        "7.0",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:L/IR:H/AR:H/MAV:A/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S",
        "7.4",
    ), // reordered: the document lists it out of order
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:H/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H",
        "8.7",
    ), // reordered: the document lists it out of order
    (
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:P",
        "8.6",
    ),
    (
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P",
        "9.7",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C",
        "8.7",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H",
        "6.4",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H/E:U/MAV:A/R:U/V:C",
        "2.4",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "10.0",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:L/MAT:P",
        "8.9",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "8.5",
    ),
    (
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/MVC:N/MVI:N/MVA:N",
        "0.0",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
        "7.1",
    ),
    (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "9.4",
    ),
];

#[test]
fn v3_1_examples() {
    assert_eq!(V3_1_EXAMPLES.len(), 28);
    for &(name, text, base) in V3_1_EXAMPLES {
        let vector: Vector3 = text.parse().unwrap();
        assert_eq!(vector.version(), Version::V3_1);
        assert_eq!(vector.base_score().to_string(), base, "{name}: {text}");
        assert_eq!(vector.to_string(), text);
    }
}

#[test]
fn v3_0_examples() {
    assert_eq!(V3_0_EXAMPLES.len(), 22);
    for &(name, text, base) in V3_0_EXAMPLES {
        let vector: Vector3 = text.parse().unwrap();
        assert_eq!(vector.version(), Version::V3_0);
        assert_eq!(vector.base_score().to_string(), base, "{name}: {text}");
        assert_eq!(vector.to_string(), text);
    }
}

#[test]
fn v4_0_examples() {
    assert!(V4_0_EXAMPLES.len() >= 60);
    for &(text, score) in V4_0_EXAMPLES {
        let vector: Vector4 = text.parse().unwrap();
        assert_eq!(vector.score().to_string(), score, "{text}");
        assert_eq!(vector.to_string(), text);
        let any: Vector = text.parse().unwrap();
        assert_eq!(any.score(), vector.score());
    }
}

#[test]
fn v4_0_specification_samples() {
    // The sample vectors of section 7 of the v4.0 specification, scored by
    // FIRST's calculator.
    let cases = [
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            "5.1",
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red",
            "5.4",
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green",
            "4.2",
        ),
    ];
    for (text, score) in cases {
        let vector: Vector4 = text.parse().unwrap();
        assert_eq!(vector.score().to_string(), score, "{text}");
    }
}

#[test]
fn v3_edge_cases() {
    // Scored by FIRST's v3.0 and v3.1 calculators.
    let cases = [
        // Highest and lowest scores.
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "10.0",
            "10.0",
            "10.0",
        ),
        (
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
            "0.0",
            "0.0",
            "0.0",
        ),
        (
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N/E:U/RL:O/RC:U",
            "1.6",
            "1.3",
            "1.3",
        ),
        // Changed scope: the v3.1 Modified Impact formula makes the
        // environmental score differ from the base score with no
        // environmental metric defined; v3.0 does not.
        (
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            "9.9",
            "9.9",
            "10.0",
        ),
        (
            "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            "9.9",
            "9.9",
            "9.9",
        ),
        (
            "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:L",
            "7.2",
            "7.2",
            "7.1",
        ),
        // Modified scope changes the PR weight and the formulas.
        (
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/MS:C",
            "8.8",
            "8.8",
            "10.0",
        ),
        (
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/MS:U",
            "9.9",
            "9.9",
            "8.8",
        ),
        // Requirements, and MISS capped at 0.915.
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H",
            "9.8",
            "9.8",
            "9.8",
        ),
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/CR:L/IR:L/AR:L",
            "7.3",
            "7.3",
            "5.8",
        ),
        // Modified impact of None everywhere scores zero.
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N",
            "9.8",
            "9.8",
            "0.0",
        ),
    ];
    for (text, base, temporal, environmental) in cases {
        let vector: Vector3 = text.parse().unwrap();
        assert_eq!(vector.base_score().to_string(), base, "base {text}");
        assert_eq!(
            vector.temporal_score().to_string(),
            temporal,
            "temporal {text}"
        );
        assert_eq!(
            vector.environmental_score().to_string(),
            environmental,
            "environmental {text}"
        );
    }
}

#[test]
fn score_bounds_hold_for_the_extremes() {
    let max: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        .parse()
        .unwrap();
    assert_eq!(max.score(), Score::MAX);
    let zero: Vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        .parse()
        .unwrap();
    assert_eq!(zero.score(), Score::ZERO);
}
