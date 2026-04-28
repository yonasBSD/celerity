//! Shared helpers for the standalone perf binaries.

#![allow(dead_code)]

use std::time::Duration;

/// Retry delay used when the sender side starts before the receiver is listening.
pub(crate) const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(200);

/// Parses a required positive integer argument and returns a readable CLI error on failure.
pub(crate) fn parse_positive_usize(
    value: Option<String>,
    name: &str,
    program: &str,
    usage_tail: &str,
) -> Result<usize, String> {
    let value = value.ok_or_else(|| usage(program, usage_tail))?;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {name}: {value}"))?;
    if parsed == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(parsed)
}

/// Formats a usage string for a perf binary.
pub(crate) fn usage(program: &str, usage_tail: &str) -> String {
    format!("usage: {program} {usage_tail}")
}

/// Formats an integer value representing hundredths into `X.YY` text.
pub(crate) fn format_hundredths(value: u128) -> String {
    format!("{}.{:02}", value / 100, value % 100)
}

/// Formats a duration as `seconds.microseconds`.
pub(crate) fn format_elapsed(elapsed: Duration) -> String {
    format!("{}.{:06}", elapsed.as_secs(), elapsed.subsec_micros())
}
