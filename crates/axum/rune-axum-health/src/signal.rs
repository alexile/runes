use crate::Error;

/// Resolves when the process is asked to stop: on Ctrl-C (`SIGINT`) and,
/// on Unix, on `SIGTERM`, the signal container orchestrators send.
///
/// Pass it to [`HealthState::graceful_shutdown`](crate::HealthState::graceful_shutdown).
/// Must be called on a Tokio runtime with the signal driver enabled.
///
/// # Errors
///
/// [`Error::Signal`] if a signal handler cannot be installed. Since
/// `graceful_shutdown` ignores the output, such an error starts shutdown
/// rather than leaving the server unable to stop.
pub async fn shutdown_signal() -> Result<(), Error> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => res?,
            _ = term.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}
