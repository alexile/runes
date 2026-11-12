//! Glue for the shared HTTP model of `rune-http-model`.

use std::time::SystemTime;

use rune_http_model::{HttpExchange, HttpRequest, HttpResponse};
use url::Url;

use crate::{CookieJar, Error, RequestContext, SetCookie, StoreOutcome};

/// Parses every `Set-Cookie` header of `response`, in wire order.
///
/// Useful for analysers that want the cookies a response sets without a
/// jar. Each header parses (or fails) on its own.
///
/// ```
/// use rune_cookie::response_set_cookies;
/// use rune_http_model::HttpResponse;
///
/// let response = HttpResponse::new(200)
///     .with_header("Set-Cookie", "sid=abc; HttpOnly")
///     .with_header("set-cookie", "broken");
/// let cookies: Vec<_> = response_set_cookies(&response).collect();
/// assert_eq!(cookies[0].as_ref().unwrap().name, "sid");
/// assert!(cookies[1].is_err());
/// ```
pub fn response_set_cookies(
    response: &HttpResponse,
) -> impl Iterator<Item = Result<SetCookie, Error>> + '_ {
    response.header_values("set-cookie").map(SetCookie::parse)
}

impl CookieJar {
    /// Stores every `Set-Cookie` of `response`, received for a request to
    /// `request_url`. Returns one result per header, in wire order; a
    /// refused cookie does not stop the others.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] if `request_url` does not parse.
    pub fn store_response(
        &mut self,
        request_url: &str,
        response: &HttpResponse,
        ctx: &RequestContext,
        now: SystemTime,
    ) -> Result<Vec<Result<StoreOutcome, Error>>, Error> {
        let url = Url::parse(request_url)?;
        Ok(response
            .header_values("set-cookie")
            .map(|header| self.store(&url, header, ctx, now))
            .collect())
    }

    /// [`CookieJar::store_response`] for an exchange's request URL and
    /// response. An exchange without a response stores nothing.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] if the request URL does not parse.
    pub fn store_exchange(
        &mut self,
        exchange: &HttpExchange,
        ctx: &RequestContext,
        now: SystemTime,
    ) -> Result<Vec<Result<StoreOutcome, Error>>, Error> {
        exchange.response.as_ref().map_or_else(
            || Ok(Vec::new()),
            |response| self.store_response(&exchange.request.url, response, ctx, now),
        )
    }

    /// Sets the `Cookie` header of `request` from the jar, replacing any
    /// existing one, and returns how many cookies it carries. With no
    /// matching cookie the request is left untouched. `ctx.safe_method` is
    /// taken from the request method.
    ///
    /// ```
    /// use std::time::SystemTime;
    /// use rune_cookie::{CookieJar, RequestContext};
    /// use rune_http_model::{HttpRequest, HttpResponse};
    ///
    /// let now = SystemTime::now();
    /// let ctx = RequestContext::http();
    /// let mut jar = CookieJar::new();
    /// let response = HttpResponse::new(200).with_header("Set-Cookie", "sid=abc; Path=/");
    /// jar.store_response("https://app.example.com/login", &response, &ctx, now)?;
    ///
    /// let mut request = HttpRequest::get("https://app.example.com/home");
    /// assert_eq!(jar.apply_to_request(&mut request, &ctx, now)?, 1);
    /// assert_eq!(request.header("cookie"), Some("sid=abc"));
    /// # Ok::<(), rune_cookie::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] if the request URL does not parse, or
    /// [`Error::NoHost`] if it has no host.
    pub fn apply_to_request(
        &mut self,
        request: &mut HttpRequest,
        ctx: &RequestContext,
        now: SystemTime,
    ) -> Result<usize, Error> {
        let url = Url::parse(&request.url)?;
        let ctx = ctx.with_method(&request.method);
        let cookies = self.cookies_for(&url, &ctx, now)?;
        let count = cookies.len();
        if count > 0 {
            let pairs: Vec<_> = cookies.iter().map(|c| c.pair()).collect();
            request.set_header("Cookie", crate::serialize_cookie_header(&pairs));
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_http_model::ExchangeId;

    #[test]
    fn exchange_round_trip() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let ctx = RequestContext::http();
        let mut jar = CookieJar::new();
        let request = HttpRequest::post("https://shop.example.com/login");
        let response = HttpResponse::new(302)
            .with_header(
                "Set-Cookie",
                "sid=1; Secure; HttpOnly; SameSite=Lax; Path=/",
            )
            .with_header("Set-Cookie", "bad; Path=/")
            .with_header("Set-Cookie", "wide=1; Domain=com");
        let exchange = HttpExchange::new(ExchangeId(1), "test", request).with_response(response);
        let results = jar.store_exchange(&exchange, &ctx, now).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Ok(StoreOutcome::Inserted));
        assert_eq!(results[1], Err(Error::MissingSeparator));
        assert!(matches!(results[2], Err(Error::Rejected(_))));

        let mut next =
            HttpRequest::get("https://shop.example.com/cart").with_header("Cookie", "old=1");
        assert_eq!(jar.apply_to_request(&mut next, &ctx, now), Ok(1));
        assert_eq!(next.header_values("cookie").collect::<Vec<_>>(), ["sid=1"]);

        // A cross-site POST navigation does not carry the Lax cookie.
        let cross = ctx.with_site(crate::SiteContext::CrossSiteTopLevelNavigation);
        let mut post = HttpRequest::post("https://shop.example.com/cart");
        assert_eq!(jar.apply_to_request(&mut post, &cross, now), Ok(0));
        assert!(!post.has_header("cookie"));

        let unanswered = HttpExchange::new(ExchangeId(2), "test", HttpRequest::get("::bad"));
        assert_eq!(jar.store_exchange(&unanswered, &ctx, now), Ok(Vec::new()));
        let mut bad = HttpRequest::get("not a url");
        assert!(matches!(
            jar.apply_to_request(&mut bad, &ctx, now),
            Err(Error::InvalidUrl(_))
        ));
    }
}
