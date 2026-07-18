use crate::database::{Cache, DB};
use chrono::Utc;
use cryptr::EncValue;
use rauthy_common::utils::get_rand;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use zeroize::Zeroizing;

const ENROLLMENT_TTL_SECS: i64 = 120;
const MAX_ATTEMPTS: i64 = 5;

#[derive(Clone, Serialize, Deserialize)]
pub struct PendingTotpEnrollment {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub mfa_mod_token_id: String,
    pub ip: IpAddr,
    pub expires_at: i64,
    secret_encrypted: Vec<u8>,
}

impl PendingTotpEnrollment {
    pub fn new(
        user_id: String,
        name: Option<String>,
        mfa_mod_token_id: String,
        ip: IpAddr,
        secret: &[u8],
    ) -> Result<Self, ErrorResponse> {
        Ok(Self {
            id: get_rand(48),
            user_id,
            name,
            mfa_mod_token_id,
            ip,
            expires_at: Utc::now().timestamp() + ENROLLMENT_TTL_SECS,
            secret_encrypted: EncValue::encrypt(secret)?.into_bytes().to_vec(),
        })
    }

    #[inline]
    fn cache_idx(id: &str) -> String {
        format!("totp_enrollment:{id}")
    }

    #[inline]
    fn attempts_idx(&self) -> String {
        format!("totp_enrollment_attempts:{}", self.id)
    }

    #[inline]
    fn consumed_idx(&self) -> String {
        format!("totp_enrollment_consumed:{}", self.id)
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        DB::hql()
            .put(
                Cache::OneTimePassword,
                Self::cache_idx(&self.id),
                self,
                Some(ENROLLMENT_TTL_SECS),
            )
            .await?;
        Ok(())
    }

    pub async fn find(id: &str) -> Result<Self, ErrorResponse> {
        DB::hql()
            .get(Cache::OneTimePassword, Self::cache_idx(id))
            .await?
            .ok_or_else(|| {
                ErrorResponse::new(
                    ErrorResponseType::NotFound,
                    "TOTP enrollment does not exist or has expired",
                )
            })
    }

    pub fn validate_binding(
        &self,
        user_id: &str,
        mfa_mod_token_id: &str,
        ip: IpAddr,
        now: i64,
    ) -> Result<(), ErrorResponse> {
        if self.expires_at < now {
            return Err(ErrorResponse::new(
                ErrorResponseType::SessionExpired,
                "TOTP enrollment has expired",
            ));
        }
        if self.user_id != user_id || self.mfa_mod_token_id != mfa_mod_token_id {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "TOTP enrollment is bound to a different user session",
            ));
        }
        if self.ip != ip {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                "TOTP enrollment is bound to a different IP",
            ));
        }
        Ok(())
    }

    pub async fn ensure_attempts_available(&self) -> Result<(), ErrorResponse> {
        let attempts = DB::hql()
            .counter_get(Cache::OneTimePassword, self.attempts_idx())
            .await?
            .unwrap_or_default();
        if attempts >= MAX_ATTEMPTS {
            return Err(Self::too_many_attempts());
        }
        Ok(())
    }

    /// Records a failed confirmation. The enrollment remains usable until the threshold.
    pub async fn record_failure(&self) -> Result<i64, ErrorResponse> {
        let attempts = DB::hql()
            .counter_add(Cache::OneTimePassword, self.attempts_idx(), 1)
            .await?;
        if attempts >= MAX_ATTEMPTS {
            self.delete().await?;
            return Err(Self::too_many_attempts());
        }
        Ok(attempts)
    }

    /// Atomically grants one caller the right to persist this enrollment.
    pub async fn claim_once(&self) -> Result<(), ErrorResponse> {
        let claims = DB::hql()
            .counter_add(Cache::OneTimePassword, self.consumed_idx(), 1)
            .await?;
        if claims != 1 {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "TOTP enrollment has already been consumed",
            ));
        }
        Ok(())
    }

    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        DB::hql()
            .delete(Cache::OneTimePassword, Self::cache_idx(&self.id))
            .await?;
        DB::hql()
            .counter_del(Cache::OneTimePassword, self.attempts_idx())
            .await?;
        Ok(())
    }

    pub fn secret(&self) -> Result<Zeroizing<Vec<u8>>, ErrorResponse> {
        Ok(Zeroizing::new(
            EncValue::try_from(self.secret_encrypted.clone())?
                .decrypt()?
                .to_vec(),
        ))
    }

    fn too_many_attempts() -> ErrorResponse {
        ErrorResponse::new(
            ErrorResponseType::TooManyRequests(Utc::now().timestamp() + ENROLLMENT_TTL_SECS),
            "Too many TOTP enrollment attempts",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::PendingTotpEnrollment;
    use rauthy_error::ErrorResponseType;
    use std::net::{IpAddr, Ipv4Addr};

    fn pending() -> PendingTotpEnrollment {
        PendingTotpEnrollment {
            id: "challenge".into(),
            user_id: "user-a".into(),
            name: None,
            mfa_mod_token_id: "token-a".into(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            expires_at: 100,
            secret_encrypted: vec![1, 2, 3],
        }
    }

    #[test]
    fn enrollment_accepts_only_its_user_token_and_ip_before_expiry() {
        assert!(
            pending()
                .validate_binding("user-a", "token-a", IpAddr::V4(Ipv4Addr::LOCALHOST), 100,)
                .is_ok()
        );
    }

    #[test]
    fn enrollment_rejects_wrong_binding_and_expiry() {
        let enrollment = pending();
        assert_eq!(
            enrollment
                .validate_binding("user-b", "token-a", IpAddr::V4(Ipv4Addr::LOCALHOST), 100,)
                .unwrap_err()
                .error,
            ErrorResponseType::Forbidden
        );
        assert_eq!(
            enrollment
                .validate_binding("user-a", "token-a", IpAddr::V4(Ipv4Addr::LOCALHOST), 101,)
                .unwrap_err()
                .error,
            ErrorResponseType::SessionExpired
        );
    }
}
