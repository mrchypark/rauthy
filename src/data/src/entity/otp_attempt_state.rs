use crate::database::DB;
use hiqlite::macros::{FromRow, params};
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::ErrorResponse;
use serde::Deserialize;

#[derive(Debug, Deserialize, FromPgRow, FromRow)]
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
                .execute_returning_map_one(sql, params!(scope_key, expires, now))
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
    use super::OtpAttemptState;
    use crate::database::DB;
    use hiqlite::macros::params;
    use hiqlite::{Node, NodeConfig};
    use rauthy_common::{DB_TYPE, DbType};
    use std::net::TcpListener;

    fn available_ports() -> (u16, u16) {
        let api = TcpListener::bind("127.0.0.1:0").unwrap();
        let raft = TcpListener::bind("127.0.0.1:0").unwrap();
        let ports = (
            api.local_addr().unwrap().port(),
            raft.local_addr().unwrap().port(),
        );
        drop((api, raft));
        ports
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attempt_window_increments_and_resets_at_expiry_with_hiqlite() {
        assert_eq!(DB_TYPE.get_or_init(|| DbType::Hiqlite), &DbType::Hiqlite);

        let (api_port, raft_port) = available_ports();
        let data_dir =
            std::env::temp_dir().join(format!("rauthy-otp-attempt-state-{}", std::process::id()));
        if data_dir.exists() {
            std::fs::remove_dir_all(&data_dir).unwrap();
        }
        std::fs::create_dir_all(&data_dir).unwrap();

        let node = Node {
            id: 1,
            addr_raft: format!("127.0.0.1:{raft_port}"),
            addr_api: format!("127.0.0.1:{api_port}"),
        };
        let mut config = NodeConfig::default();
        config.node_id = 1;
        config.nodes = vec![node];
        config.listen_addr_api = "127.0.0.1".into();
        config.listen_addr_raft = "127.0.0.1".into();
        config.data_dir = data_dir.to_string_lossy().into_owned().into();
        config.filename_db = "otp-attempt-state.db".into();
        config.secret_raft = "otp-attempt-state-raft".to_string();
        config.secret_api = "otp-attempt-state-api".to_string();
        config.enc_keys = cryptr::EncKeys::generate().unwrap();
        config.cache_storage_disk = false;
        config.health_check_delay_secs = 0;
        config.raft_config = NodeConfig::default_raft_config(100);

        DB::init(config).await.unwrap();
        DB::hql()
            .execute(
                r#"CREATE TABLE otp_attempt_state
(
    scope_key TEXT NOT NULL PRIMARY KEY,
    attempts  INTEGER NOT NULL,
    expires   INTEGER NOT NULL
) STRICT"#,
                params!(),
            )
            .await
            .unwrap();

        let now = 1_000_000;
        let ttl = 60;
        let first = OtpAttemptState::increment("totp:test", now, ttl)
            .await
            .unwrap();
        assert_eq!(first.attempts, 1);
        assert_eq!(first.expires, now + ttl);

        let second = OtpAttemptState::increment("totp:test", now + 1, ttl)
            .await
            .unwrap();
        assert_eq!(second.attempts, 2);
        assert_eq!(second.expires, first.expires);

        let reset = OtpAttemptState::increment("totp:test", first.expires, ttl)
            .await
            .unwrap();
        assert_eq!(reset.attempts, 1);
        assert_eq!(reset.expires, first.expires + ttl);

        DB::hql().shutdown().await.unwrap();
        std::fs::remove_dir_all(data_dir).unwrap();
    }
}
