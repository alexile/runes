//! A small built-in ruleset, written for this crate.

use crate::Ruleset;

/// Category names of the built-in ruleset, in the Wappalyzer
/// `categories.json` shape. The numbering is this crate's own.
pub const BUILTIN_CATEGORIES: &str = r#"{
  "1": { "name": "CMS" },
  "2": { "name": "Web servers" },
  "3": { "name": "Programming languages" },
  "4": { "name": "JavaScript libraries" },
  "5": { "name": "JavaScript frameworks" },
  "6": { "name": "Web frameworks" },
  "7": { "name": "CDN" },
  "8": { "name": "Analytics" },
  "9": { "name": "UI frameworks" },
  "10": { "name": "Databases" },
  "11": { "name": "Reverse proxies" }
}"#;

/// The built-in technologies, in the Wappalyzer `technologies` shape.
///
/// A deliberately small set of very common technologies, written for this
/// crate from their documented, publicly visible markers (`Server` and
/// `X-Powered-By` tokens, default cookie names, generator tags, asset
/// paths). It is a working example and a test fixture, not a replacement
/// for a maintained ruleset: load one with
/// [`Ruleset::extend_from_wappalyzer_json`] after checking its licence.
pub const BUILTIN_TECHNOLOGIES: &str = r#"{
  "Nginx": {
    "cats": [2, 11],
    "website": "https://nginx.org",
    "headers": { "Server": "^nginx(?:/([\\d.]+))?\\;version:\\1" }
  },
  "Apache HTTP Server": {
    "cats": [2],
    "website": "https://httpd.apache.org",
    "headers": { "Server": "^Apache(?:/([\\d.]+))?(?:\\s|$)\\;version:\\1" }
  },
  "Microsoft IIS": {
    "cats": [2],
    "website": "https://www.iis.net",
    "headers": { "Server": "^Microsoft-IIS(?:/([\\d.]+))?\\;version:\\1" },
    "implies": "Microsoft ASP.NET\\;confidence:50"
  },
  "Microsoft ASP.NET": {
    "cats": [6],
    "website": "https://dotnet.microsoft.com/apps/aspnet",
    "headers": {
      "X-Powered-By": "^ASP\\.NET",
      "X-AspNet-Version": "([\\d.]+)\\;version:\\1"
    },
    "cookies": { "ASP.NET_SessionId": "" }
  },
  "PHP": {
    "cats": [3],
    "website": "https://www.php.net",
    "headers": {
      "X-Powered-By": "^PHP(?:/([\\d.]+))?\\;version:\\1",
      "Server": "PHP(?:/([\\d.]+))?\\;version:\\1"
    },
    "cookies": { "PHPSESSID": "" },
    "url": "\\.php(?:$|\\?)"
  },
  "MySQL": {
    "cats": [10],
    "website": "https://www.mysql.com"
  },
  "WordPress": {
    "cats": [1],
    "website": "https://wordpress.org",
    "meta": { "generator": "^WordPress ?([\\d.]+)?\\;version:\\1" },
    "html": "<link[^>]+/wp-(?:content|includes)/",
    "scriptSrc": "/wp-(?:content|includes)/",
    "headers": { "Link": "rel=\"https://api\\.w\\.org/\"" },
    "implies": ["PHP", "MySQL\\;confidence:50"]
  },
  "Drupal": {
    "cats": [1],
    "website": "https://www.drupal.org",
    "meta": { "generator": "^Drupal(?:\\s([\\d.]+))?\\;version:\\1" },
    "headers": { "X-Generator": "^Drupal(?:\\s([\\d.]+))?\\;version:\\1", "X-Drupal-Cache": "" },
    "scriptSrc": "/(?:misc|core/misc)/drupal\\.js",
    "implies": "PHP"
  },
  "Joomla": {
    "cats": [1],
    "website": "https://www.joomla.org",
    "meta": { "generator": "^Joomla!(?: ([\\d.]+))?\\;version:\\1" },
    "implies": "PHP"
  },
  "Laravel": {
    "cats": [6],
    "website": "https://laravel.com",
    "cookies": { "laravel_session": "" },
    "implies": "PHP"
  },
  "Express": {
    "cats": [6],
    "website": "https://expressjs.com",
    "headers": { "X-Powered-By": "^Express$" },
    "implies": "Node.js"
  },
  "Node.js": {
    "cats": [3],
    "website": "https://nodejs.org"
  },
  "jQuery": {
    "cats": [4],
    "website": "https://jquery.com",
    "scriptSrc": [
      "jquery[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1",
      "/jquery/([\\d.]+)/jquery(?:\\.min)?\\.js\\;version:\\1",
      "jquery(?:\\.min)?\\.js\\;confidence:50"
    ]
  },
  "Bootstrap": {
    "cats": [9],
    "website": "https://getbootstrap.com",
    "scriptSrc": [
      "bootstrap(?:\\.bundle)?(?:\\.min)?\\.js\\;confidence:50",
      "/bootstrap@([\\d.]+)/\\;version:\\1"
    ],
    "html": "<link[^>]+bootstrap(?:\\.min)?\\.css\\;confidence:50"
  },
  "React": {
    "cats": [5],
    "website": "https://react.dev",
    "html": "<[^>]+data-reactroot",
    "scriptSrc": "/react(?:-dom)?(?:@([\\d.]+))?(?:/umd)?/react(?:-dom)?\\.(?:production|development)\\.min\\.js\\;version:\\1"
  },
  "Next.js": {
    "cats": [5],
    "website": "https://nextjs.org",
    "headers": { "X-Powered-By": "^Next\\.js ?([\\d.]+)?\\;version:\\1" },
    "html": "<script[^>]+id=\"__NEXT_DATA__\"",
    "scriptSrc": "/_next/static/",
    "implies": ["React", "Node.js"]
  },
  "Google Analytics": {
    "cats": [8],
    "website": "https://marketingplatform.google.com/about/analytics/",
    "scriptSrc": "googletagmanager\\.com/gtag/js|google-analytics\\.com/(?:ga|analytics)\\.js",
    "cookies": { "_ga": "" }
  },
  "Cloudflare": {
    "cats": [7],
    "website": "https://www.cloudflare.com",
    "headers": { "Server": "^cloudflare$", "CF-RAY": "" },
    "cookies": { "__cf_bm": "" }
  }
}"#;

/// The built-in ruleset: [`BUILTIN_TECHNOLOGIES`] with
/// [`BUILTIN_CATEGORIES`].
#[must_use]
pub fn builtin_ruleset() -> Ruleset {
    let mut rules = Ruleset::new();
    // Both are constants checked by the tests; a bad one is a bug there,
    // and an empty ruleset beats panicking.
    let _ = rules.extend_categories_from_json(BUILTIN_CATEGORIES);
    let _ = rules.extend_from_wappalyzer_json(BUILTIN_TECHNOLOGIES);
    rules
}
