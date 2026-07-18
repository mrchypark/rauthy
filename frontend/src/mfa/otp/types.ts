import type { MfaPurpose } from '$api/types/mfa';
import type { OtpKind, OtpResponse } from '$api/types/otp';

export type { OtpKind } from '$api/types/otp';

export type OtpAdditionalData = undefined | OtpLoginFinishResponse | OtpServiceReq;

export interface OtpAuthStartRequest {
    otp_id: string;
    purpose: MfaPurpose;
}

export interface OtpAuthStartResult {
    error?: string;
    data?: OtpAuthStartResponse;
}

export interface OtpAuthStartResponse {
    code: string;
}

export interface OtpAuthFinishRequest {
    code: string;
    otp_code: string;
}

export interface OtpAuthFinishResult {
    error?: string;
    data?: OtpAdditionalData;
}

export interface OtpLoginFinishResponse {
    loc: string;
}

export interface OtpServiceReq {
    code: string;
}

export interface OtpCreateRequest {
    otp_name?: string;
    otp_kind: OtpKind;
    mfa_mod_token_id: string;
}

export interface TotpEnrollmentResponse {
    enrollment_id: string;
    secret_base32: string;
    otpauth_uri: string;
    qr_code_base64: string;
    /// Unix timestamp in seconds
    expires_at: number;
}

export interface OtpCreateData {
    otp: OtpResponse;
    enrollment?: TotpEnrollmentResponse;
}

export interface OtpCreateResponse {
    error?: string;
    data?: OtpCreateData;
}

export interface OtpActivateRequest {
    otp_id: string;
    otp_code: string;
    mfa_mod_token_id: string;
}

export interface OtpActivateResponse {
    error?: string;
    data?: null;
}

export interface OtpDeleteRequest {
    otp_id: string;
    mfa_mod_token_id?: string;
}

export interface OtpDeleteResponse {
    error?: string;
    data?: null;
}
