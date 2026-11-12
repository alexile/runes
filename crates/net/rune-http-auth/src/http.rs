//! Glue for the shared HTTP model of `rune-http-model`.

use rune_http_model::{HttpRequest, HttpResponse};

use crate::{AuthError, Challenge, DigestRequest};

/// The challenges of a response: `Proxy-Authenticate` for a 407,
/// `WWW-Authenticate` otherwise, across every header field in order.
///
/// ```
/// use rune_http_auth::response_challenges;
/// use rune_http_model::HttpResponse;
///
/// let response = HttpResponse::new(401)
///     .with_header("WWW-Authenticate", "Negotiate, NTLM")
///     .with_header("www-authenticate", "Basic realm=\"intranet\"");
/// let schemes: Vec<_> = response_challenges(&response)
///     .unwrap()
///     .into_iter()
///     .map(|c| c.scheme)
///     .collect();
/// assert_eq!(schemes, ["Negotiate", "NTLM", "Basic"]);
/// ```
///
/// # Errors
///
/// The first header value that does not parse.
pub fn response_challenges(response: &HttpResponse) -> Result<Vec<Challenge>, AuthError> {
    let name = if response.status == 407 {
        "proxy-authenticate"
    } else {
        "www-authenticate"
    };
    let mut out = Vec::new();
    for value in response.header_values(name) {
        out.extend(Challenge::parse_list(value)?);
    }
    Ok(out)
}

/// The request's parsed `Authorization` credentials, if any.
#[must_use]
pub fn request_credentials(request: &HttpRequest) -> Option<Result<Challenge, AuthError>> {
    request.header("authorization").map(Challenge::parse)
}

/// Sets the `Authorization` header (replacing any previous one).
pub fn set_authorization(request: &mut HttpRequest, value: impl Into<String>) {
    request.set_header("Authorization", value);
}

/// The request-target Digest signs (`uri`): the path and query of the
/// request URL, or the URL as-is when it does not parse as absolute.
#[must_use]
pub fn digest_uri(request: &HttpRequest) -> String {
    request.parsed_url().map_or_else(
        |_| request.url.clone(),
        |url| {
            url.query().map_or_else(
                || url.path().to_owned(),
                |query| format!("{}?{query}", url.path()),
            )
        },
    )
}

/// Digest inputs for `request`: its method, [`digest_uri`] and body, with
/// the given `uri` buffer, client nonce and nonce count.
///
/// ```
/// use rune_http_auth::{DigestChallenge, digest_request, digest_uri, set_authorization};
/// use rune_http_model::HttpRequest;
///
/// let mut request = HttpRequest::get("https://host.example/dir/index.html?x=1");
/// let uri = digest_uri(&request);
/// assert_eq!(uri, "/dir/index.html?x=1");
/// let challenge = DigestChallenge::new("realm", "nonce");
/// let response = challenge.respond("u", "p", &digest_request(&request, &uri, "cnonce", 1));
/// set_authorization(&mut request, response.to_string());
/// assert!(request.header("Authorization").unwrap().starts_with("Digest "));
/// ```
#[must_use]
pub fn digest_request<'a>(
    request: &'a HttpRequest,
    uri: &'a str,
    cnonce: &'a str,
    nc: u32,
) -> DigestRequest<'a> {
    DigestRequest::new(&request.method, uri)
        .with_body(request.body.as_bytes())
        .with_cnonce(cnonce)
        .with_nc(nc)
}
