use crate::{
    api_cookie::ApiCookie,
    database::{
        Cache::{self},
        DB,
    },
    email::otp::send_email_otp,
    entity::{
        auth_codes::AuthCodeToSAwait,
        browser_id::BrowserId,
        login_locations::LoginLocation,
        sessions::{MfaMethod, Session},
        users::User,
    },
    rauthy_config::RauthyConfig,
};
use actix_web::{
    HttpRequest, HttpResponse, HttpResponseBuilder,
    cookie::Cookie,
    http::{
        StatusCode,
        header::{
            self, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_METHODS, HeaderValue,
        },
    },
};
use chrono::Utc;
use cryptr::{EncKeys, EncValue};
use hiqlite::macros::params;
use rauthy_api_types::{
    tos::ToSAwaitLoginResponse,
    users::{
        MfaPurpose, OtpAuthFinishRequest, OtpAuthStartRequest, OtpAuthStartResponse,
        OtpGetResponse, OtpLoginFinishResponse,
    },
};
use rauthy_common::{
    constants::COOKIE_MFA,
    is_hiqlite,
    utils::{base64_decode, base64_encode, deserialize, get_rand, serialize},
};
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use ring::{
    digest,
    hmac::{self},
    rand::{self},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    ops::Add,
    str::FromStr,
};
use time::OffsetDateTime;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::info;
use utoipa::ToSchema;
use zeroize::Zeroizing;

const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP_SECONDS: u64 = 30;

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum OtpKind {
    #[default]
    Email,
    Phone,
    Time,
}

impl OtpKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            OtpKind::Email => "email",
            OtpKind::Phone => "phone",
            OtpKind::Time => "time",
        }
    }

    pub fn is_enabled(self) -> bool {
        let otp = &RauthyConfig::get().vars.otp;
        otp.enable
            && match self {
                Self::Email => otp.email.enable,
                Self::Time => otp.time.enable,
                Self::Phone => false,
            }
    }
}

impl Display for OtpKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for OtpKind {
    type Err = ErrorResponse;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "email" => Ok(Self::Email),
            "time" => Ok(Self::Time),
            "phone" => Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "phone OTP is not implemented",
            )),
            _ => Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "invalid OTP kind",
            )),
        }
    }
}

pub struct TotpEnrollment {
    secret: Zeroizing<Vec<u8>>,
    pub manual_secret: String,
    pub otpauth_uri: String,
    pub qr_base64: String,
}

impl TotpEnrollment {
    pub fn generate(issuer: String, account_name: String) -> Result<Self, ErrorResponse> {
        let secret = Zeroizing::new(
            Secret::generate_secret()
                .to_bytes()
                .map_err(|err| ErrorResponse::new(ErrorResponseType::Internal, err.to_string()))?,
        );
        let totp = OneTimePassword::totp(secret.as_slice(), Some(issuer), account_name)?;
        let manual_secret = Secret::Raw(secret.to_vec()).to_encoded().to_string();
        let otpauth_uri = totp.get_url();
        let qr_base64 = totp
            .get_qr_base64()
            .map_err(|err| ErrorResponse::new(ErrorResponseType::Internal, err))?;

        Ok(Self {
            secret,
            manual_secret,
            otpauth_uri,
            qr_base64,
        })
    }

    pub fn secret(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

#[derive(Clone, Serialize, Deserialize, FromPgRow)]
pub struct OneTimePassword {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub secret: Vec<u8>,
    pub enc_key_id: String,
    pub last_used: i64,
    pub last_used_step: i64,
    #[column(parse)]
    pub kind: OtpKind,
    pub is_active: bool,
}

impl Debug for OneTimePassword {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OneTimePassword {{ id: {}(...), user_id: {}, name: {:?}, enc_key_id: {}, last_used: {}, last_used_step: {}, kind: {}, is_active: {} }}",
            &self.id[..5],
            self.user_id,
            self.name,
            self.enc_key_id,
            self.last_used,
            self.last_used_step,
            self.kind,
            self.is_active
        )
    }
}

// CRUD
impl OneTimePassword {
    pub async fn create(
        user_id: String,
        name: Option<String>,
        kind: OtpKind,
    ) -> Result<Self, ErrorResponse> {
        if kind != OtpKind::Email {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "use create_totp for time-based OTP",
            ));
        }
        // if the len is longer than the algorithm it will be compressed by the digest
        // if the len is shorter than the algorithm it will be padded with 0x30
        let secret = Zeroizing::new(
            rand::generate::<[u8; digest::SHA512_OUTPUT_LEN]>(&rand::SystemRandom::new())?
                .expose()
                .to_vec(),
        );
        Self::insert(user_id, name, kind, secret.as_slice(), false).await
    }

    pub async fn create_totp(
        user_id: String,
        name: Option<String>,
        secret: &[u8],
    ) -> Result<Self, ErrorResponse> {
        Self::totp(secret, None, String::new())?;
        Self::insert(user_id, name, OtpKind::Time, secret, true).await
    }

    async fn insert(
        user_id: String,
        name: Option<String>,
        kind: OtpKind,
        secret: &[u8],
        is_active: bool,
    ) -> Result<Self, ErrorResponse> {
        let enc_key_id = EncKeys::get_static().enc_key_active.clone();
        let otp = Self {
            id: get_rand(64),
            user_id,
            name,
            secret: EncValue::encrypt(secret)?.into_bytes().to_vec(),
            enc_key_id,
            last_used: 0,
            last_used_step: 0,
            kind,
            is_active,
        };

        let sql = r#"
INSERT INTO one_time_password
    (id, user_id, name, secret, enc_key_id, last_used, last_used_step, kind, is_active)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#;

        if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(
                        otp.id.clone(),
                        otp.user_id.clone(),
                        otp.name.clone(),
                        otp.secret.clone(),
                        otp.enc_key_id.clone(),
                        otp.last_used,
                        otp.last_used_step,
                        otp.kind.as_str(),
                        otp.is_active
                    ),
                )
                .await?;
        } else {
            DB::pg_execute(
                sql,
                &[
                    &otp.id,
                    &otp.user_id,
                    &otp.name,
                    &otp.secret,
                    &otp.enc_key_id,
                    &otp.last_used,
                    &otp.last_used_step,
                    &otp.kind.as_str(),
                    &otp.is_active,
                ],
            )
            .await?;
        }

        Ok(otp)
    }

    pub async fn delete_all_otp_for_user(user_id: &str) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM one_time_password WHERE user_id = $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(user_id)).await?;
        } else {
            DB::pg_execute(sql, &[&user_id]).await?;
        };

        Ok(())
    }

    pub async fn delete(id: &str) -> Result<(), ErrorResponse> {
        let sql = "DELETE FROM one_time_password WHERE id = $1";
        if is_hiqlite() {
            DB::hql().execute(sql, params!(id)).await?;
        } else {
            DB::pg_execute(sql, &[&id]).await?;
        };

        Ok(())
    }

    pub async fn find(id: &str) -> Result<Self, ErrorResponse> {
        let sql = "SELECT * FROM one_time_password WHERE id = $1";
        let res = if is_hiqlite() {
            DB::hql().query_as_one(sql, params!(id)).await?
        } else {
            DB::pg_query_one(sql, &[&id]).await?
        };

        Ok(res)
    }

    pub async fn find_by_id_for_user(
        otp_id: &String,
        user_id: &String,
    ) -> Result<Self, ErrorResponse> {
        let sql = "SELECT * FROM one_time_password WHERE id = $1 AND user_id = $2";
        let res = if is_hiqlite() {
            DB::hql()
                .query_as_one(sql, params!(otp_id, user_id))
                .await?
        } else {
            DB::pg_query_one(sql, &[&otp_id, &user_id]).await?
        };

        Ok(res)
    }

    pub async fn find_active_by_id_for_user(
        otp_id: &str,
        user_id: &str,
    ) -> Result<Self, ErrorResponse> {
        if !RauthyConfig::get().vars.otp.enable {
            return Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "otp does not exist",
            ));
        }
        let sql =
            "SELECT * FROM one_time_password WHERE id = $1 AND user_id = $2 AND is_active = $3";
        let res = if is_hiqlite() {
            DB::hql()
                .query_as_one(sql, params!(otp_id, user_id, true))
                .await?
        } else {
            DB::pg_query_one(sql, &[&otp_id, &user_id, &true]).await?
        };
        Ok(res)
    }

    pub async fn find_kind_for_user(
        kind: &OtpKind,
        user_id: &String,
    ) -> Result<Self, ErrorResponse> {
        let sql = "SELECT * FROM one_time_password WHERE user_id = $1 AND kind = $2";
        let res = if is_hiqlite() {
            DB::hql()
                .query_as_one(sql, params!(user_id, kind.as_str()))
                .await?
        } else {
            DB::pg_query_one(sql, &[&user_id, &kind.as_str()]).await?
        };

        Ok(res)
    }

    pub async fn find_for_user(user_id: &String) -> Result<Vec<Self>, ErrorResponse> {
        let sql = "SELECT * FROM one_time_password WHERE user_id = $1";
        let res = if is_hiqlite() {
            DB::hql().query_as(sql, params!(user_id)).await?
        } else {
            DB::pg_query(sql, &[&user_id], 1).await?
        };

        Ok(res)
    }

    pub async fn find_active_for_user(user_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        if !RauthyConfig::get().vars.otp.enable {
            return Ok(Vec::new());
        }
        let sql = "SELECT * FROM one_time_password WHERE user_id = $1 AND is_active = $2";
        let mut res: Vec<Self> = if is_hiqlite() {
            DB::hql().query_as(sql, params!(user_id, true)).await?
        } else {
            DB::pg_query(sql, &[&user_id, &true], 1).await?
        };
        res.retain(|otp| otp.kind.is_enabled());
        Ok(res)
    }

    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        let sql = "SELECT * FROM one_time_password";
        if is_hiqlite() {
            Ok(DB::hql().query_as(sql, params!()).await?)
        } else {
            Ok(DB::pg_query(sql, &[], 8).await?)
        }
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        let sql =
            "UPDATE one_time_password SET name = $1, last_used = $2, is_active = $3 WHERE id = $4";
        if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(&self.name, self.last_used, self.is_active, &self.id),
                )
                .await?;
        } else {
            DB::pg_execute(
                sql,
                &[&self.name, &self.last_used, &self.is_active, &self.id],
            )
            .await?;
        }

        Ok(())
    }

    pub async fn re_encrypt_secret(&mut self, new_kid: &str) -> Result<(), ErrorResponse> {
        let plaintext = self.secret_cleartext()?;
        let secret = EncValue::encrypt_with_key_id(plaintext.as_slice(), new_kid.to_owned())?
            .into_bytes()
            .to_vec();
        let sql = "UPDATE one_time_password SET secret = $1, enc_key_id = $2 WHERE id = $3";
        let rows_affected = if is_hiqlite() {
            DB::hql()
                .execute(sql, params!(secret.clone(), new_kid, &self.id))
                .await?
        } else {
            DB::pg_execute(sql, &[&secret, &new_kid, &self.id]).await?
        };
        if rows_affected != 1 {
            return Err(ErrorResponse::new(
                ErrorResponseType::Internal,
                "OTP secret disappeared during key rotation",
            ));
        }
        self.secret = secret;
        self.enc_key_id = new_kid.to_owned();
        Ok(())
    }
}

impl OneTimePassword {
    const DIGITS_POWER: [u32; 9] = [
        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
    ];

    fn generate_otp(secret: &[u8], step: i64, digest_len: u16, code_len: u8) -> String {
        let msg = step.to_be_bytes();
        let algorithm = match digest_len {
            256 => hmac::HMAC_SHA256,
            384 => hmac::HMAC_SHA384,
            512 => hmac::HMAC_SHA512,
            _ => hmac::HMAC_SHA512,
        };
        let key = hmac::Key::new(algorithm, secret);
        let hash = hmac::sign(&key, &msg);
        let hash = hash.as_ref();

        // Unreachable should never panic since the tag should never be empty
        let offset = match hash.last() {
            Some(e) => (e & 0xf) as usize,
            None => unreachable!(),
        };

        let binary = [
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ];
        let binary = u32::from_be_bytes(binary);

        let otp = binary % Self::DIGITS_POWER[code_len as usize];

        format!("{:0width$}", otp, width = code_len as usize)
    }

    fn totp(
        secret: &[u8],
        issuer: Option<String>,
        account_name: String,
    ) -> Result<TOTP, ErrorResponse> {
        TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP_SECONDS,
            secret.to_vec(),
            issuer,
            account_name,
        )
        .map_err(|err| ErrorResponse::new(ErrorResponseType::BadRequest, err.to_string()))
    }

    fn secret_cleartext(&self) -> Result<Zeroizing<Vec<u8>>, ErrorResponse> {
        Ok(Zeroizing::new(
            EncValue::try_from(self.secret.clone())?.decrypt()?.to_vec(),
        ))
    }

    pub fn match_totp_step(
        secret: &[u8],
        code: &str,
        unix_time: u64,
    ) -> Result<Option<i64>, ErrorResponse> {
        if code.len() != TOTP_DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "TOTP code must contain exactly 6 digits",
            ));
        }
        let totp = Self::totp(secret, None, String::new())?;
        let current_step = unix_time / TOTP_STEP_SECONDS;
        for candidate_step in current_step.saturating_sub(1)..=current_step.saturating_add(1) {
            if totp.generate(candidate_step * TOTP_STEP_SECONDS) == code {
                return Ok(Some(candidate_step as i64));
            }
        }
        Ok(None)
    }

    async fn accept_totp_at(
        &self,
        user_id: &str,
        code: &str,
        unix_time: u64,
    ) -> Result<(), ErrorResponse> {
        let secret = self.secret_cleartext()?;
        let Some(matched_step) = Self::match_totp_step(secret.as_slice(), code, unix_time)? else {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "code is incorrect",
            ));
        };
        let last_used = unix_time as i64;
        let sql = r#"
UPDATE one_time_password
SET last_used = $1, last_used_step = $2
WHERE id = $3 AND user_id = $4 AND kind = $5 AND is_active = $6
  AND last_used_step < $2"#;
        let rows_affected = if is_hiqlite() {
            DB::hql()
                .execute(
                    sql,
                    params!(
                        last_used,
                        matched_step,
                        &self.id,
                        user_id,
                        OtpKind::Time.as_str(),
                        true
                    ),
                )
                .await?
        } else {
            DB::pg_execute(
                sql,
                &[
                    &last_used,
                    &matched_step,
                    &self.id,
                    &user_id,
                    &OtpKind::Time.as_str(),
                    &true,
                ],
            )
            .await?
        };
        if rows_affected == 1 {
            Ok(())
        } else {
            Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "TOTP code was already used or the factor is inactive",
            ))
        }
    }

    pub async fn activate(&mut self) -> Result<(), ErrorResponse> {
        self.is_active = true;
        self.save().await
    }

    pub async fn validate(&self, user_id: &str, code: &str) -> Result<(), ErrorResponse> {
        if self.user_id != user_id {
            return Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "otp does not exist",
            ));
        }
        if !self.kind.is_enabled() {
            return Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "otp does not exist",
            ));
        }
        match self.kind {
            OtpKind::Email => {
                let current_time = OffsetDateTime::now_utc().unix_timestamp();
                let timeout = (current_time - self.last_used) / 60;
                if timeout >= RauthyConfig::get().vars.otp.exp as i64 {
                    return Err(ErrorResponse::new(
                        ErrorResponseType::BadRequest,
                        "otp code expired",
                    ));
                }
                let valid_code = Self::generate_otp(
                    self.secret_cleartext()?.as_slice(),
                    self.last_used,
                    RauthyConfig::get().vars.otp.default_digest_len,
                    RauthyConfig::get().vars.otp.length,
                );
                if code != valid_code {
                    return Err(ErrorResponse::new(
                        ErrorResponseType::BadRequest,
                        "code is incorrect",
                    ));
                }
            }
            OtpKind::Time => {
                self.accept_totp_at(
                    user_id,
                    code,
                    OffsetDateTime::now_utc().unix_timestamp() as u64,
                )
                .await?;
            }
            OtpKind::Phone => {
                return Err(ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    "phone OTP is not implemented",
                ));
            }
        };

        Ok(())
    }

    pub async fn request_otp(&mut self) -> Result<(), ErrorResponse> {
        if !self.kind.is_enabled() {
            return Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "otp does not exist",
            ));
        }
        if self.kind == OtpKind::Time {
            return Ok(());
        }
        let user = User::find(self.user_id.clone()).await?;

        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let code = Self::generate_otp(
            self.secret_cleartext()?.as_slice(),
            current_time,
            RauthyConfig::get().vars.otp.default_digest_len,
            RauthyConfig::get().vars.otp.length,
        );
        self.last_used = current_time;
        self.save().await?;
        match self.kind {
            OtpKind::Email => {
                send_email_otp(&code, &user).await;
            }
            OtpKind::Time => {}
            OtpKind::Phone => {
                return Err(ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    "phone OTP is not implemented",
                ));
            }
        };
        Ok(())
    }
}

impl From<OneTimePassword> for OtpGetResponse {
    fn from(value: OneTimePassword) -> Self {
        Self {
            id: value.id,
            name: value.name,
            last_used: value.last_used,
            kind: value.kind.to_string(),
            is_active: value.is_active,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtpCookie {
    pub email: String,
    pub exp: OffsetDateTime,
}

impl OtpCookie {
    pub fn new(email: String) -> Self {
        let renew = RauthyConfig::get().vars.otp.renew_exp as i64;
        let exp = OffsetDateTime::now_utc().add(::time::Duration::hours(renew));
        Self { email, exp }
    }

    pub fn build(&self) -> Result<Cookie<'_>, ErrorResponse> {
        let set = serialize(self)?;
        let enc = EncValue::encrypt(&set)?.into_bytes();
        let b64 = base64_encode(&enc);

        let max_age = self.exp.unix_timestamp() - Utc::now().timestamp();
        Ok(ApiCookie::build(COOKIE_MFA, b64, max_age))
    }

    pub fn parse_validate(cookie: &Option<String>) -> Result<Self, ErrorResponse> {
        if cookie.is_none() {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "One time password Cookie is missing",
            ));
        }
        let cookie = cookie.as_ref().unwrap();
        let bytes = base64_decode(cookie)?;
        let dec = EncValue::try_from(bytes)?.decrypt()?;
        let slf = deserialize::<Self>(&dec)?;

        if slf.exp < OffsetDateTime::now_utc() {
            Err(ErrorResponse::new(
                ErrorResponseType::SessionExpired,
                "One time password Cookie has expired",
            ))
        } else {
            Ok(slf)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpData {
    pub code: String,
    pub otp_id: String,
    pub data: OtpAdditionalData,
}

// CRUD
impl OtpData {
    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        DB::hql()
            .delete(Cache::OneTimePassword, self.code.clone())
            .await?;
        Ok(())
    }

    pub async fn find(code: String) -> Result<Self, ErrorResponse> {
        let res = DB::hql().get(Cache::OneTimePassword, code).await?;
        match res {
            None => Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "Otp Data not found",
            )),
            Some(res) => Ok(res),
        }
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        let ttl = Some(RauthyConfig::get().vars.otp.exp as i64 * 60);
        DB::hql()
            .put(Cache::OneTimePassword, self.code.clone(), &self, ttl)
            .await?;
        Ok(())
    }
}

// This is the data, that will be passed to the client as response to a successful MFA auth
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum OtpAdditionalData {
    Login(OtpLoginReq),
    Service(OtpServiceReq),
    Test(String), // saves the User ID
    LoginToSAwait(OtpLoginToSAwaitCode),
}

impl OtpAdditionalData {
    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        match self {
            Self::Login(d) => d.delete().await,
            // The service req data is not deleted here, but actually further down the road
            // after the service req has been made.
            Self::Service(_) => Ok(()),
            Self::Test(_) => Ok(()),
            Self::LoginToSAwait(_) => Ok(()),
        }
    }

    pub fn into_response(self) -> HttpResponse {
        match self {
            Self::Login(login_req) => {
                let header_loc = (
                    header::LOCATION,
                    HeaderValue::from_str(&login_req.header_loc).unwrap(),
                );

                let mut builder = if login_req.needs_user_update {
                    HttpResponse::ResetContent()
                } else {
                    let mut builder = HttpResponse::Accepted();
                    builder.insert_header(header_loc);
                    builder
                };

                if let Some(value) = login_req.header_origin {
                    builder.insert_header((
                        header::ACCESS_CONTROL_ALLOW_ORIGIN,
                        HeaderValue::from_str(&value).unwrap(),
                    ));
                }

                if login_req.needs_user_update {
                    builder.finish()
                } else {
                    builder.json(OtpLoginFinishResponse {
                        loc: login_req.header_loc,
                    })
                }
            }
            Self::Service(svc_req) => HttpResponse::Accepted().json(svc_req),
            Self::Test(_) => HttpResponse::Accepted().finish(),
            Self::LoginToSAwait(tos_req) => {
                let mut resp = HttpResponseBuilder::new(StatusCode::from_u16(206).unwrap()).json(
                    &ToSAwaitLoginResponse {
                        tos_await_code: tos_req.await_code,
                        force_accept: None,
                    },
                );
                if let Some(origin) = tos_req.header_origin {
                    resp.headers_mut()
                        .insert(header::ORIGIN, HeaderValue::from_str(&origin).unwrap());
                    resp.headers_mut().insert(
                        ACCESS_CONTROL_ALLOW_METHODS,
                        HeaderValue::from_static("POST"),
                    );
                    resp.headers_mut().insert(
                        ACCESS_CONTROL_ALLOW_CREDENTIALS,
                        HeaderValue::from_static("true"),
                    );
                }
                resp
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OtpLoginReq {
    pub code: String,
    pub user_id: String,
    pub header_loc: String,
    pub header_origin: Option<String>,
    pub tos_await_data: Option<OtpToSAwaitData>,
    pub needs_user_update: bool,
    /// Restricts a factor-choice continuation to the selected OTP kind.
    pub otp_kind: Option<OtpKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OtpToSAwaitData {
    pub auth_code: String,
    pub auth_code_lifetime: i32,
}

// CRUD
impl OtpLoginReq {
    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        DB::hql()
            .delete(Cache::OneTimePassword, self.code.clone())
            .await?;
        Ok(())
    }

    pub async fn find(code: &String) -> Result<Self, ErrorResponse> {
        let res: Option<Self> = DB::hql().get(Cache::OneTimePassword, code).await?;
        match res {
            None => Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "OneTimePassword Login Request Data not found",
            )),
            Some(res) => Ok(res),
        }
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        let ttl = Some(RauthyConfig::get().vars.otp.exp as i64 * 60);
        DB::hql()
            .put(Cache::OneTimePassword, self.code.clone(), self, ttl)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OtpServiceReq {
    pub code: String,
    pub user_id: String,
}

// CRUD
impl OtpServiceReq {
    pub fn new(user_id: String) -> Self {
        Self {
            code: get_rand(48),
            user_id,
        }
    }

    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        DB::hql()
            .delete(Cache::OneTimePassword, self.code.clone())
            .await?;
        Ok(())
    }

    pub async fn find(code: String) -> Result<Self, ErrorResponse> {
        let res = DB::hql().get(Cache::OneTimePassword, code).await?;
        match res {
            None => Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "OTP Service Request Data not found",
            )),
            Some(res) => Ok(res),
        }
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        let ttl = Some(RauthyConfig::get().vars.otp.exp as i64 * 60);
        DB::hql()
            .put(Cache::OneTimePassword, self.code.clone(), self, ttl)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OtpLoginToSAwaitCode {
    await_code: String,
    user_id: String,
    header_origin: Option<String>,
}

pub async fn auth_start(
    user_id: Option<String>,
    payload: &OtpAuthStartRequest,
) -> Result<OtpAuthStartResponse, ErrorResponse> {
    if !RauthyConfig::get().vars.otp.enable {
        return Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "otp does not exist",
        ));
    }
    let is_test = matches!(&payload.purpose, MfaPurpose::Test);
    let (add_data, user_id, required_kind) = match &payload.purpose {
        MfaPurpose::Login(code) => {
            debug_assert!(user_id.is_none());
            let d = OtpLoginReq::find(code).await?;
            let user_id = d.user_id.clone();
            let required_kind = d.otp_kind;
            (OtpAdditionalData::Login(d), user_id, required_kind)
        }
        MfaPurpose::MfaModToken
        | MfaPurpose::PamLogin
        | MfaPurpose::PasswordNew
        | MfaPurpose::PasswordReset => {
            let user_id = user_id.expect("user_id should always exist for non-login otp starts");
            let svc_req = OtpServiceReq::new(user_id.clone());
            svc_req.save().await?;
            (OtpAdditionalData::Service(svc_req), user_id, None)
        }
        MfaPurpose::Test => {
            let user_id = user_id.expect("user_id should always exist for non-login otp starts");
            (OtpAdditionalData::Test(user_id.clone()), user_id, None)
        }
    };

    let mut otp = if is_test {
        OneTimePassword::find_by_id_for_user(&payload.otp_id, &user_id).await?
    } else {
        OneTimePassword::find_active_by_id_for_user(&payload.otp_id, &user_id).await?
    };
    if !otp.kind.is_enabled() {
        return Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "otp does not exist",
        ));
    }
    if required_kind.is_some_and(|kind| kind != otp.kind) {
        return Err(ErrorResponse::new(
            ErrorResponseType::NotFound,
            "otp does not exist",
        ));
    }
    otp.request_otp().await?;

    add_data.delete().await?;
    let auth_data = OtpData {
        code: get_rand(48),
        otp_id: payload.otp_id.clone(),
        data: add_data,
    };
    auth_data.save().await?;

    Ok(OtpAuthStartResponse {
        code: auth_data.code,
    })
}

pub async fn auth_finish(
    req: &HttpRequest,
    browser_id: BrowserId,
    session: Option<Session>,
    payload: OtpAuthFinishRequest,
) -> Result<OtpAdditionalData, ErrorResponse> {
    let auth_data = OtpData::find(payload.code).await?;

    let (user_id, is_login) = match &auth_data.data {
        OtpAdditionalData::Login(d) => (&d.user_id, true),
        OtpAdditionalData::Service(d) => (&d.user_id, false),
        OtpAdditionalData::Test(user_id) => (user_id, false),
        OtpAdditionalData::LoginToSAwait(d) => (&d.user_id, false),
    };

    let otp = OneTimePassword::find(&auth_data.otp_id).await?;
    match otp.validate(user_id, &payload.otp_code).await {
        Ok(_) => {
            auth_data.delete().await?;
            let mut user = User::find(user_id.clone()).await?;

            LoginLocation::spawn_background_check(user.clone(), req, browser_id)?;

            if is_login && let Some(mut session) = session {
                session
                    .set_authenticated_with_mfa(&user, MfaMethod::Totp)
                    .await?;
                user.last_login = Some(Utc::now().timestamp());
                user.last_failed_login = None;
                user.failed_login_attempts = None;
                user.save(None).await?;
            }

            info!(
                user.id = user_id,
                "OneTimePassword Authentication succesful"
            );

            if let OtpAdditionalData::Login(data) = auth_data.data {
                data.delete().await?;

                if let Some(tos_data) = data.tos_await_data {
                    let code_await = AuthCodeToSAwait {
                        auth_code: tos_data.auth_code,
                        await_code: AuthCodeToSAwait::generate_code(),
                        auth_code_lifetime: tos_data.auth_code_lifetime,
                        header_loc: data.header_loc,
                        header_origin: data.header_origin.clone(),
                        needs_user_update: data.needs_user_update,
                    };
                    code_await.save().await?;

                    Ok(OtpAdditionalData::LoginToSAwait(OtpLoginToSAwaitCode {
                        await_code: code_await.await_code,
                        user_id: user.id,
                        header_origin: data.header_origin,
                    }))
                } else {
                    Ok(OtpAdditionalData::Login(data))
                }
            } else {
                Ok(auth_data.data)
            }
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use crate::entity::one_time_password::{OneTimePassword, OtpKind};
    use std::str::FromStr;

    #[test]
    fn otp_kind_rejects_unknown_and_unimplemented_phone_values() {
        assert_eq!(OtpKind::from_str("email").unwrap(), OtpKind::Email);
        assert_eq!(OtpKind::from_str("time").unwrap(), OtpKind::Time);
        assert!(OtpKind::from_str("phone").is_err());
        assert!(OtpKind::from_str("unknown").is_err());
    }

    #[test]
    fn totp_match_identifies_each_allowed_time_step() {
        let secret = b"12345678901234567890";

        assert_eq!(
            OneTimePassword::match_totp_step(secret, "755224", 59).unwrap(),
            Some(0)
        );
        assert_eq!(
            OneTimePassword::match_totp_step(secret, "287082", 59).unwrap(),
            Some(1)
        );
        assert_eq!(
            OneTimePassword::match_totp_step(secret, "359152", 59).unwrap(),
            Some(2)
        );
        assert_eq!(
            OneTimePassword::match_totp_step(secret, "000000", 59).unwrap(),
            None
        );
        assert!(OneTimePassword::match_totp_step(secret, "12345x", 59).is_err());
    }

    #[test]
    fn test_hotp_rfc_6238() {
        let seed32 = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32,
        ];
        let seed64 = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
        ];
        let steps = 30;

        let mut t = 59 / steps;
        assert_eq!(
            OneTimePassword::generate_otp(&seed32, t, 256, 8),
            "46119246"
        );
        assert_eq!(
            OneTimePassword::generate_otp(&seed64, t, 512, 8),
            "90693936"
        );

        t = 1111111109 / steps;
        assert_eq!(
            OneTimePassword::generate_otp(&seed32, t, 256, 8),
            "68084774"
        );
        assert_eq!(
            OneTimePassword::generate_otp(&seed64, t, 512, 8),
            "25091201"
        );

        t = 1111111111 / steps;
        assert_eq!(
            OneTimePassword::generate_otp(&seed32, t, 256, 8),
            "67062674"
        );
        assert_eq!(
            OneTimePassword::generate_otp(&seed64, t, 512, 8),
            "99943326"
        );

        t = 1234567890 / steps;
        assert_eq!(
            OneTimePassword::generate_otp(&seed32, t, 256, 8),
            "91819424"
        );
        assert_eq!(
            OneTimePassword::generate_otp(&seed64, t, 512, 8),
            "93441116"
        );

        t = 2000000000 / steps;
        assert_eq!(
            OneTimePassword::generate_otp(&seed32, t, 256, 8),
            "90698825"
        );
        assert_eq!(
            OneTimePassword::generate_otp(&seed64, t, 512, 8),
            "38618901"
        );

        t = 20000000000 / steps;
        assert_eq!(
            OneTimePassword::generate_otp(&seed32, t, 256, 8),
            "77737706"
        );
        assert_eq!(
            OneTimePassword::generate_otp(&seed64, t, 512, 8),
            "47863826"
        );
    }
}
