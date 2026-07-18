use crate::database::DB;
use hiqlite::macros::params;
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::ErrorResponse;
use serde::Deserialize;

#[derive(Debug, Deserialize, FromPgRow)]
pub struct OtpAttemptState {
    pub attempts: i64,
    pub expires: i64,
}

impl OtpAttemptState {
    /// Atomically increments an active window or starts a fresh one after expiry.
    pub async fn increment(
        scope_key: &str,
        now: i64,
        ttl_secs: i64,
    ) -> Result<Self, ErrorResponse> {
        let expires = now.saturating_add(ttl_secs);
        let sql = r#"
INSERT INTO otp_attempt_state (scope_key, attempts, expires)
VALUES ($1, 1, $2)
ON CONFLICT(scope_key) DO UPDATE SET
    attempts = CASE WHEN otp_attempt_state.expires <= $3
                    THEN 1 ELSE otp_attempt_state.attempts + 1 END,
    expires = CASE WHEN otp_attempt_state.expires <= $3
                  THEN $2 ELSE otp_attempt_state.expires END
RETURNING attempts, expires"#;
        if is_hiqlite() {
            Ok(DB::hql()
                .query_as_one(sql, params!(scope_key, expires, now))
                .await?)
        } else {
            Ok(DB::pg_query_one(sql, &[&scope_key, &expires, &now]).await?)
        }
    }

    pub async fn find_active(scope_key: &str, now: i64) -> Result<Option<Self>, ErrorResponse> {
        let sql =
            "SELECT attempts, expires FROM otp_attempt_state WHERE scope_key = $1 AND expires > $2";
        if is_hiqlite() {
            Ok(DB::hql()
                .query_as_optional(sql, params!(scope_key, now))
                .await?)
        } else {
            Ok(DB::pg_query_opt(sql, &[&scope_key, &now]).await?)
        }
    }

    pub async fn delete(scope_key: &str) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM otp_attempt_state WHERE scope_key = $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(scope_key)).await?;
        } else {
            DB::pg_execute(sql, &[&scope_key]).await?;
        }
        Ok(())
    }

    pub async fn delete_expired(now: i64) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM otp_attempt_state WHERE expires <= $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(now)).await?;
        } else {
            DB::pg_execute(sql, &[&now]).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn expiry_window_resets_at_boundary() {
        fn next(current: Option<(i64, i64)>, now: i64, ttl: i64) -> (i64, i64) {
            match current {
                Some((attempts, expires)) if expires > now => (attempts + 1, expires),
                _ => (1, now + ttl),
            }
        }

        assert_eq!(next(Some((4, 101)), 100, 60), (5, 101));
        assert_eq!(next(Some((5, 100)), 100, 60), (1, 160));
    }
}
