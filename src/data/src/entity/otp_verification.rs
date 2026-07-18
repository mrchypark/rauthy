use crate::database::{Cache, DB};
use chrono::Utc;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

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

    fn challenge_key(challenge: &str, ip: IpAddr) -> String {
        format!("otp_verify:challenge:{challenge}:{ip}")
    }

    fn user_key(user_id: &str) -> String {
        format!("otp_verify:user:{user_id}")
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
        let user_ip: Option<i64> = DB::hql()
            .get(Cache::OneTimePassword, Self::block_key(user_id, ip))
            .await?;
        let user: Option<i64> = DB::hql()
            .get(Cache::OneTimePassword, Self::user_block_key(user_id))
            .await?;
        if let Some(retry_at) = user_ip.or(user) {
            return Err(Self::rate_limited(retry_at));
        }
        Ok(())
    }

    pub async fn ensure_challenge_available(challenge: &str) -> Result<(), ErrorResponse> {
        if let Some(retry_at) = DB::hql()
            .get(Cache::OneTimePassword, Self::challenge_block_key(challenge))
            .await?
        {
            return Err(Self::rate_limited(retry_at));
        }
        Ok(())
    }

    /// Serializes verification for one challenge across the cluster.
    pub async fn claim(
        user_id: &str,
        ip: IpAddr,
        challenge: &str,
        ttl: i64,
    ) -> Result<(), ErrorResponse> {
        let claims = DB::hql()
            .counter_add(Cache::OneTimePassword, Self::claim_key(challenge), 1)
            .await?;
        if claims == 1 {
            let user_id = user_id.to_string();
            let challenge = challenge.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl.max(1) as u64)).await;
                let _ = Self::cleanup(&user_id, ip, &challenge).await;
            });
            Ok(())
        } else {
            Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "OTP challenge is already being verified or was consumed",
            ))
        }
    }

    pub async fn release(challenge: &str) -> Result<(), ErrorResponse> {
        DB::hql()
            .counter_del(Cache::OneTimePassword, Self::claim_key(challenge))
            .await?;
        Ok(())
    }

    pub async fn record_failure(
        user_id: &str,
        ip: IpAddr,
        challenge: &str,
    ) -> Result<(), ErrorResponse> {
        let identity = DB::hql()
            .counter_add(Cache::OneTimePassword, Self::identity_key(user_id, ip), 1)
            .await?;
        let user = DB::hql()
            .counter_add(Cache::OneTimePassword, Self::user_key(user_id), 1)
            .await?;
        let challenge_attempts = DB::hql()
            .counter_add(
                Cache::OneTimePassword,
                Self::challenge_key(challenge, ip),
                1,
            )
            .await?;
        let challenge_global = DB::hql()
            .counter_add(
                Cache::OneTimePassword,
                Self::challenge_global_key(challenge),
                1,
            )
            .await?;
        if identity >= MAX_ATTEMPTS
            || user >= MAX_ATTEMPTS
            || challenge_attempts >= MAX_ATTEMPTS
            || challenge_global >= MAX_ATTEMPTS
        {
            let retry_at = Utc::now().timestamp() + BLOCK_SECS;
            for key in [
                Self::block_key(user_id, ip),
                Self::user_block_key(user_id),
                Self::challenge_block_key(challenge),
            ] {
                DB::hql()
                    .put(Cache::OneTimePassword, key, &retry_at, Some(BLOCK_SECS))
                    .await?;
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
        Self::cleanup(user_id, ip, challenge).await?;
        Ok(())
    }

    pub async fn cleanup(user_id: &str, ip: IpAddr, challenge: &str) -> Result<(), ErrorResponse> {
        for key in [
            Self::identity_key(user_id, ip),
            Self::user_key(user_id),
            Self::challenge_key(challenge, ip),
            Self::challenge_global_key(challenge),
            Self::claim_key(challenge),
        ] {
            DB::hql().counter_del(Cache::OneTimePassword, key).await?;
        }
        Ok(())
    }

    pub async fn cleanup_unknown(challenge: &str, ip: IpAddr) -> Result<(), ErrorResponse> {
        for key in [
            Self::challenge_key(challenge, ip),
            Self::challenge_global_key(challenge),
            Self::claim_key(challenge),
        ] {
            DB::hql().counter_del(Cache::OneTimePassword, key).await?;
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
        Self::cleanup(user_id, ip, challenge).await
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
    fn repeated_challenges_share_the_user_ip_limit() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            OtpVerificationAttempt::identity_key("user", ip),
            OtpVerificationAttempt::identity_key("user", ip)
        );
        assert_ne!(
            OtpVerificationAttempt::challenge_key("first", ip),
            OtpVerificationAttempt::challenge_key("second", ip)
        );
    }

    #[test]
    fn identity_limit_is_scoped_by_user_and_ip() {
        let first = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let second = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert_ne!(
            OtpVerificationAttempt::identity_key("user-a", first),
            OtpVerificationAttempt::identity_key("user-b", first)
        );
        assert_ne!(
            OtpVerificationAttempt::identity_key("user-a", first),
            OtpVerificationAttempt::identity_key("user-a", second)
        );
        assert_eq!(
            OtpVerificationAttempt::user_key("user-a"),
            OtpVerificationAttempt::user_key("user-a")
        );
        assert_eq!(
            OtpVerificationAttempt::challenge_global_key("challenge"),
            OtpVerificationAttempt::challenge_global_key("challenge")
        );
    }
}
