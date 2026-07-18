use crate::database::{Cache, DB};
use crate::entity::otp_attempt_state::OtpAttemptState;
use chrono::Utc;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const MAX_ATTEMPTS: i64 = 5;
const BLOCK_SECS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumedOtpChallenge {
    pub user_id: String,
    pub kind: String,
}

pub struct OtpVerificationAttempt;

impl OtpVerificationAttempt {
    fn identity_key(user_id: &str, ip: IpAddr) -> String {
        format!("otp_verify:user:{user_id}:{ip}")
    }
    fn user_key(user_id: &str) -> String {
        format!("otp_verify:user:{user_id}")
    }
    fn challenge_key(challenge: &str, ip: IpAddr) -> String {
        format!("otp_verify:challenge:{challenge}:{ip}")
    }
    fn challenge_global_key(challenge: &str) -> String {
        format!("otp_verify:challenge:{challenge}")
    }
    fn claim_key(challenge: &str) -> String {
        format!("otp_verify:claim:{challenge}")
    }
    fn block_key(user_id: &str, ip: IpAddr) -> String {
        format!("otp_verify:block:{user_id}:{ip}")
    }
    fn user_block_key(user_id: &str) -> String {
        format!("otp_verify:block:user:{user_id}")
    }
    fn challenge_block_key(challenge: &str) -> String {
        format!("otp_verify:block:challenge:{challenge}")
    }
    fn consumed_key(challenge: &str) -> String {
        format!("otp_verify:consumed:{challenge}")
    }

    pub async fn ensure_identity_available(user_id: &str, ip: IpAddr) -> Result<(), ErrorResponse> {
        let now = Utc::now().timestamp();
        OtpAttemptState::delete_expired(now).await?;
        for key in [Self::block_key(user_id, ip), Self::user_block_key(user_id)] {
            if let Some(state) = OtpAttemptState::find_active(&key, now).await? {
                return Err(Self::rate_limited(state.expires));
            }
        }
        Ok(())
    }

    pub async fn ensure_challenge_available(challenge: &str) -> Result<(), ErrorResponse> {
        let now = Utc::now().timestamp();
        if let Some(state) =
            OtpAttemptState::find_active(&Self::challenge_block_key(challenge), now).await?
        {
            return Err(Self::rate_limited(state.expires));
        }
        Ok(())
    }

    pub async fn claim(
        _user_id: &str,
        _ip: IpAddr,
        challenge: &str,
        ttl: i64,
    ) -> Result<(), ErrorResponse> {
        let state =
            OtpAttemptState::increment(&Self::claim_key(challenge), Utc::now().timestamp(), ttl)
                .await?;
        if state.attempts == 1 {
            Ok(())
        } else {
            Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "OTP challenge is already being verified or was consumed",
            ))
        }
    }

    pub async fn release(challenge: &str) -> Result<(), ErrorResponse> {
        OtpAttemptState::delete(&Self::claim_key(challenge)).await
    }

    pub async fn record_failure(
        user_id: &str,
        ip: IpAddr,
        challenge: &str,
    ) -> Result<(), ErrorResponse> {
        let now = Utc::now().timestamp();
        let keys = [
            Self::identity_key(user_id, ip),
            Self::user_key(user_id),
            Self::challenge_key(challenge, ip),
            Self::challenge_global_key(challenge),
        ];
        let mut limited = false;
        for key in &keys {
            limited |= OtpAttemptState::increment(key, now, BLOCK_SECS)
                .await?
                .attempts
                >= MAX_ATTEMPTS;
        }
        if limited {
            for key in &keys {
                OtpAttemptState::delete(key).await?;
            }
            let mut retry_at = now + BLOCK_SECS;
            for key in [
                Self::block_key(user_id, ip),
                Self::user_block_key(user_id),
                Self::challenge_block_key(challenge),
            ] {
                retry_at = retry_at.max(
                    OtpAttemptState::increment(&key, now, BLOCK_SECS)
                        .await?
                        .expires,
                );
            }
            return Err(Self::rate_limited(retry_at));
        }
        Ok(())
    }

    pub async fn success(
        user_id: &str,
        ip: IpAddr,
        challenge: &str,
        kind: &str,
        ttl: i64,
    ) -> Result<(), ErrorResponse> {
        DB::hql()
            .put(
                Cache::OneTimePassword,
                Self::consumed_key(challenge),
                &ConsumedOtpChallenge {
                    user_id: user_id.to_string(),
                    kind: kind.to_string(),
                },
                Some(ttl),
            )
            .await?;
        Self::cleanup(user_id, ip, challenge, true).await
    }

    async fn cleanup(
        user_id: &str,
        ip: IpAddr,
        challenge: &str,
        include_blocks: bool,
    ) -> Result<(), ErrorResponse> {
        let mut keys = vec![
            Self::identity_key(user_id, ip),
            Self::user_key(user_id),
            Self::challenge_key(challenge, ip),
            Self::challenge_global_key(challenge),
            Self::claim_key(challenge),
        ];
        if include_blocks {
            keys.extend([
                Self::block_key(user_id, ip),
                Self::user_block_key(user_id),
                Self::challenge_block_key(challenge),
            ]);
        }
        for key in keys {
            OtpAttemptState::delete(&key).await?;
        }
        Ok(())
    }

    pub async fn cleanup_unknown(challenge: &str, ip: IpAddr) -> Result<(), ErrorResponse> {
        for key in [
            Self::challenge_key(challenge, ip),
            Self::challenge_global_key(challenge),
            Self::claim_key(challenge),
        ] {
            OtpAttemptState::delete(&key).await?;
        }
        Ok(())
    }

    pub async fn terminate(
        user_id: &str,
        ip: IpAddr,
        challenge: &str,
        kind: &str,
        ttl: i64,
    ) -> Result<(), ErrorResponse> {
        DB::hql()
            .put(
                Cache::OneTimePassword,
                Self::consumed_key(challenge),
                &ConsumedOtpChallenge {
                    user_id: user_id.to_string(),
                    kind: kind.to_string(),
                },
                Some(ttl),
            )
            .await?;
        Self::cleanup(user_id, ip, challenge, false).await
    }

    pub async fn consumed(challenge: &str) -> Result<Option<ConsumedOtpChallenge>, ErrorResponse> {
        Ok(DB::hql()
            .get(Cache::OneTimePassword, Self::consumed_key(challenge))
            .await?)
    }

    fn rate_limited(retry_at: i64) -> ErrorResponse {
        ErrorResponse::new(
            ErrorResponseType::TooManyRequests(retry_at),
            "Too many OTP verification attempts",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::OtpVerificationAttempt;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn user_and_challenge_scopes_do_not_depend_on_ip() {
        let first = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let second = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(
            OtpVerificationAttempt::user_key("user"),
            OtpVerificationAttempt::user_key("user")
        );
        assert_eq!(
            OtpVerificationAttempt::challenge_global_key("challenge"),
            OtpVerificationAttempt::challenge_global_key("challenge")
        );
        assert_ne!(
            OtpVerificationAttempt::identity_key("user", first),
            OtpVerificationAttempt::identity_key("user", second)
        );
    }
}
