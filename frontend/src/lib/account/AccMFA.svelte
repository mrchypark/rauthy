<script lang="ts">
    import Button from '$lib5/button/Button.svelte';
    import { onMount, untrack } from 'svelte';
    import Input from '$lib5/form/Input.svelte';
    import { useI18n } from '$state/i18n.svelte.js';
    import { useSession } from '$state/session.svelte.js';
    import { fetchDelete, fetchGet, fetchPost } from '$api/fetch';
    import type { PasskeyResponse, WebauthnDeleteRequest } from '$api/types/webauthn.ts';
    import type { UserResponse } from '$api/types/user.ts';
    import { PATTERN_OTP_CODE, PATTERN_USER_NAME } from '$utils/patterns';
    import { webauthnReg } from '$mfa/webauthn/registration';
    import WebauthnRequest from '$lib5/WebauthnRequest.svelte';
    import type { WebauthnAdditionalData, WebauthnServiceReq } from '$mfa/webauthn/types.ts';
    import UserPasskey from '$lib5/UserPasskey.svelte';
    import type { MfaModTokenResponse, UserMfaTokenRequest } from '$api/types/mfa_mod_token';
    import Modal from '$lib/Modal.svelte';
    import InputPassword from '$lib/form/InputPassword.svelte';
    import Form from '$lib/form/Form.svelte';
    import IconArrowPathSquare from '$icons/IconArrowPathSquare.svelte';
    import Template from '$lib5/Template.svelte';
    import { TPL_OTP_LENGTH, TPL_IS_OTP_ENABLED } from '$utils/constants';
    import type { OtpResponse } from '$api/types/otp';
    import { otpActivate, otpDelete, otpRequest } from '$mfa/otp/mod';
    import type { MfaPurpose } from '$api/types/mfa';
    import type {
        OtpAdditionalData,
        OtpKind,
        OtpServiceReq,
        TotpEnrollmentResponse,
    } from '$mfa/otp/types';
    import UserOtp from '$lib5/UserOtp.svelte';
    import OtpRequest from '$lib5/OtpRequest.svelte';

    let { user }: { user: UserResponse } = $props();

    const isWebauthnSupported = 'credentials' in navigator;

    let t = useI18n();
    let session = useSession('account');
    let userId = $derived(session.get()?.user_id);

    let refInput: undefined | HTMLInputElement = $state();
    let refPkAuthBtn: undefined | HTMLButtonElement = $state();

    let err = $state(false);
    let pwdErr = $state('');
    let msg = $state('');
    let showRegInput = $state(false);
    let showOtpRegistration = $state(false);
    let showOtpInput = $state(false);
    let showDelete = $state(untrack(() => user.account_type) === 'password');

    let mfaPurpose: undefined | MfaPurpose = $state();
    let mfaKind: undefined | 'webauthn' | 'otp' = $state();
    let passkeyName = $state('');
    let isInputError = $state(false);
    let isLoading = $state(false);
    let isOtpLoading = $state(false);

    let showModal = $state(false);
    let closeModal: undefined | (() => void) = $state();

    let passkeys: PasskeyResponse[] = $state([]);
    let mfaModToken: undefined | MfaModTokenResponse = $state();
    let mfaModSecs: undefined | number = $state();
    let interval: undefined | number;
    let enrollmentInterval: undefined | number;

    let isOtpEnabled = $state(false);
    let otpSize = $state(6);
    let otps: OtpResponse[] = $state([]);
    let otpKind: OtpKind = $state('email');
    let pendingOtpKind: undefined | OtpKind = $state();
    let pendingEnrollment: undefined | TotpEnrollmentResponse = $state();
    let enrollmentSecs: undefined | number = $state();
    let otpName = $state('');
    let otpId: undefined | string = $state();
    let hasOtp = $derived(otps.some(otp => otp.is_active));
    let pendingCodeSize = $derived(pendingOtpKind === 'time' ? 6 : otpSize);

    onMount(() => {
        fetchPasskeys();
        return () => {
            clearInterval(interval);
            clearInterval(enrollmentInterval);
        };
    });

    $effect(() => {
        if (isOtpEnabled) {
            fetchOtps();
        } else {
            otps = [];
            cancelOtpEnrollment();
        }
    });

    $effect(() => {
        if (passkeys.length > 0 && user.account_type === 'passkey') {
            showDelete = passkeys.length > 1;
        }
    });

    $effect(() => {
        refInput?.focus();
    });

    $effect(() => {
        refPkAuthBtn?.focus();
    });

    function calcModSecs() {
        let modSecs = 0;
        if (mfaModToken) {
            let ts = new Date().getTime() / 1000;
            modSecs = Math.floor(mfaModToken.exp - ts);
        }
        if (modSecs > 0) {
            mfaModSecs = modSecs;
        } else {
            mfaModSecs = undefined;
            mfaModToken = undefined;
            clearInterval(interval);
            interval = undefined;
        }
    }

    function resetMsgErr() {
        err = false;
        msg = '';
    }

    async function fetchPasskeys() {
        err = false;

        let res = await fetchGet<PasskeyResponse[]>(
            `/auth/v1/users/${session.get()?.user_id}/webauthn`,
        );
        if (res.body) {
            passkeys = res.body;
        } else {
            err = true;
        }
    }

    async function handleRegister() {
        resetMsgErr();

        if (isInputError || !userId) {
            return;
        }
        if (passkeyName.length < 1) {
            err = true;
            msg = t.mfa.passkeyNameErr;
            return;
        }

        let tokenId = mfaModToken?.id;
        if (!tokenId) {
            showModal = true;
            return;
        }

        let res = await webauthnReg(
            userId,
            passkeyName,
            t.authorize.invalidKeyUsed,
            t.authorize.requestExpired,
            undefined,
            undefined,
            tokenId,
        );
        if (res.error) {
            err = true;
            msg = `${t.mfa.errorReg} - ${res.error}`;
        } else {
            showRegInput = false;
            passkeyName = '';
            await fetchPasskeys();
        }
    }

    async function handleDelete(name: string) {
        if (!mfaModToken) {
            showModal = true;
            return;
        }

        let payload: WebauthnDeleteRequest = {
            mfa_mod_token_id: mfaModToken.id,
        };
        let res = await fetchDelete(`/auth/v1/users/${user.id}/webauthn/delete/${name}`, payload);
        if (res.status === 200) {
            await fetchPasskeys();
        } else {
            msg = res.error?.message || 'Error';
        }
    }

    function onRegisterClick() {
        if (mfaModToken) {
            showRegInput = true;
        } else {
            showModal = true;
        }
    }

    async function fetchOtps() {
        err = false;

        let res = await fetchGet<OtpResponse[]>(`/auth/v1/users/${session.get()?.user_id}/otp`);
        if (res.body) {
            otps = res.body;
        } else {
            err = true;
        }
    }

    async function handleCreateOtp(_form: HTMLFormElement, params: URLSearchParams) {
        resetMsgErr();
        let kind = params.get('otp-kind');
        if (isInputError || !userId || (kind !== 'email' && kind !== 'time')) {
            return;
        }

        let tokenId = mfaModToken?.id;
        if (!tokenId) {
            showModal = true;
            return;
        }
        isOtpLoading = true;
        otpKind = kind;
        otpName = params.get('otp-name') || '';
        let res = await otpRequest(userId, otpKind, otpName || undefined, tokenId);
        isOtpLoading = false;
        if (res.data) {
            otpId = res.data.enrollment?.enrollment_id || res.data.otp.id;
            pendingOtpKind = otpKind;
            pendingEnrollment = res.data.enrollment;
            otps = [...otps.filter(otp => otp.id !== res.data?.otp.id), res.data.otp];
            showOtpRegistration = false;
            showOtpInput = true;
            if (pendingEnrollment) {
                startEnrollmentTimer(pendingEnrollment.expires_at);
            }
        } else {
            err = true;
            msg = `${t.mfa.errorReg} - ${res.error}`;
        }
    }

    async function handleActivateOtp(_form: HTMLFormElement, params: URLSearchParams) {
        resetMsgErr();

        if (isInputError || !userId || !showOtpInput || !otpId) {
            return;
        }

        let tokenId = mfaModToken?.id;
        if (!tokenId) {
            showModal = true;
            showOtpInput = false;
            return;
        }

        isOtpLoading = true;
        let res = await otpActivate(userId, otpId, params.get('otp') || '', tokenId);
        isOtpLoading = false;
        if (res.error) {
            err = true;
            msg = res.error || 'Error';
        } else {
            cancelOtpEnrollment();
            msg = t.mfa.otp.registered;
            await fetchOtps();
        }
    }

    function startEnrollmentTimer(expiresAt: number) {
        clearInterval(enrollmentInterval);
        let update = () => {
            enrollmentSecs = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
            if (enrollmentSecs === 0) {
                cancelOtpEnrollment();
                err = true;
                msg = t.mfa.otp.expired;
            }
        };
        update();
        enrollmentInterval = window.setInterval(update, 1000);
    }

    function cancelOtpEnrollment() {
        let pendingId = otpId;
        clearInterval(enrollmentInterval);
        enrollmentInterval = undefined;
        showOtpInput = false;
        pendingEnrollment = undefined;
        pendingOtpKind = undefined;
        enrollmentSecs = undefined;
        otpId = undefined;
        otpName = '';
        if (pendingId) {
            otps = otps.filter(otp => otp.id !== pendingId || otp.is_active);
        }
    }

    async function handleDeleteOtp(otpId: string) {
        resetMsgErr();

        if (isInputError || !userId || !otpId) {
            return;
        }

        let tokenId = mfaModToken?.id;
        if (!tokenId) {
            showModal = true;
            return;
        }

        let res = await otpDelete(userId, otpId, tokenId);
        if (res.error) {
            err = true;
            msg = res.error || 'Error';
        } else {
            await fetchOtps();
        }
    }

    async function onMfaTokenSubmit(_form: HTMLFormElement, params: URLSearchParams) {
        pwdErr = '';
        isLoading = true;

        let payload: UserMfaTokenRequest = {
            password: params.get('password') || '',
        };
        await fetchMfaToken(payload);
        isLoading = false;
    }

    async function fetchMfaToken(payload: UserMfaTokenRequest) {
        let res = await fetchPost<MfaModTokenResponse>(
            `/auth/v1/users/${user.id}/mfa_token`,
            payload,
        );
        if (res.body) {
            mfaModToken = res.body;
            closeModal?.();

            if (interval) {
                clearInterval(interval);
            }

            calcModSecs();
            interval = window.setInterval(() => {
                calcModSecs();
            }, 1000);
        } else {
            pwdErr = t.mfa.passwordInvalid;
        }
    }

    function mfaTokenRefresh() {
        mfaModToken = undefined;
        showModal = true;
    }

    async function onMfaTokenWebauthnSubmit() {
        closeModal?.();
        mfaPurpose = 'MfaModToken';
        mfaKind = 'webauthn';
    }

    async function onMfaTokenOtpSubmit() {
        closeModal?.();
        mfaPurpose = 'MfaModToken';
        mfaKind = 'otp';
    }

    function onMfaError(error: string) {
        mfaPurpose = undefined;
        mfaKind = undefined;
        err = true;
        msg = error;
        setTimeout(() => {
            err = false;
            msg = '';
        }, 5000);
    }

    function onMfaSuccess(data?: WebauthnAdditionalData | OtpAdditionalData) {
        if (mfaPurpose === 'MfaModToken' && mfaKind === 'webauthn') {
            if (!data) {
                console.error('did not receive WebauthnData after SvcReq');
                return;
            }
            let svc = data as WebauthnServiceReq;
            let payload: UserMfaTokenRequest = {
                mfa_code: svc.code,
            };
            fetchMfaToken(payload);
        } else if (mfaPurpose === 'MfaModToken' && mfaKind === 'otp') {
            if (!data) {
                console.error('did not receive OtpData after SvcReq');
                return;
            }
            let svc = data as OtpServiceReq;
            let payload: UserMfaTokenRequest = {
                mfa_code: svc.code,
            };
            fetchMfaToken(payload);
        } else {
            msg = t.mfa.testSuccess;
            setTimeout(() => {
                msg = '';
            }, 3000);
        }

        mfaKind = undefined;
        mfaPurpose = undefined;
    }
</script>

<Template id={TPL_IS_OTP_ENABLED} bind:value={isOtpEnabled} />
<Template id={TPL_OTP_LENGTH} bind:value={otpSize} />

<div class="container">
    {#if mfaModSecs && mfaModSecs > 0}
        <div class="modToken">
            <div>
                {t.account.canModifyFor}
                <span class="timeLeft">
                    {mfaModSecs}
                    {t.common.seconds}
                </span>
            </div>
            <Button ariaLabel={t.common.refresh} invisible onclick={mfaTokenRefresh}>
                <div class="btnRefresh">
                    <IconArrowPathSquare />
                </div>
            </Button>
        </div>
    {/if}
    <b>{t.mfa.webauthn.title}</b>
    {#if !isWebauthnSupported}
        <div class="err">
            <b>{t.mfa.webauthn.unsupportedText}</b>
        </div>
    {:else}
        {#if mfaPurpose && mfaKind == 'webauthn'}
            <WebauthnRequest purpose={mfaPurpose} onSuccess={onMfaSuccess} onError={onMfaError} />
        {/if}

        <p>
            {t.mfa.webauthn.p1}
            <br /><br />
            {t.mfa.webauthn.p2}
            <br /><br />
            {t.mfa.webauthn.p3}
            <a href="https://sebadob.github.io/rauthy/config/passkeys.html"
                >{t.mfa.webauthn.docLinkText}</a
            >.
        </p>

        {#if showRegInput}
            <Input
                bind:ref={refInput}
                bind:value={passkeyName}
                autocomplete="off"
                label={t.mfa.passkeyName}
                placeholder={t.mfa.passkeyName}
                maxLength={32}
                pattern={PATTERN_USER_NAME}
                bind:isError={isInputError}
                onEnter={handleRegister}
            />
            <div class="regBtns">
                <Button onclick={handleRegister}>{t.mfa.register}</Button>
                <Button level={3} onclick={() => (showRegInput = false)}>{t.common.cancel}</Button>
            </div>
        {:else}
            <div class="regNewBtn">
                <Button level={passkeys.length === 0 ? 1 : 2} onclick={onRegisterClick}>
                    {t.mfa.registerNew}
                </Button>
            </div>
        {/if}

        {#if passkeys.length > 0}
            <div class="keysHeader">
                {t.mfa.registerdKeys}
            </div>
        {/if}
        <div class="keysContainer">
            {#each passkeys as passkey (passkey.name)}
                <UserPasskey {passkey} {showDelete} onDelete={handleDelete} />
            {/each}
        </div>

        {#if passkeys.length > 0}
            <div class="button">
                <Button
                    onclick={() => {
                        mfaPurpose = 'Test';
                        mfaKind = 'webauthn';
                    }}>{t.mfa.test}</Button
                >
            </div>
        {/if}

        <div class:success={!err} class:err>
            {msg}
        </div>
    {/if}
    {#if isOtpEnabled}
        <b>{t.mfa.otp.title}</b>

        {#if mfaPurpose && mfaKind == 'otp'}
            <OtpRequest
                activeOtps={otps}
                purpose={mfaPurpose}
                onSuccess={onMfaSuccess}
                onError={onMfaError}
            />
        {/if}

        {#if showOtpInput}
            {#if pendingOtpKind === 'time' && pendingEnrollment}
                <div class="totpSetup">
                    <p>{t.mfa.otp.timeSetup}</p>
                    <img
                        class="qrCode"
                        src={`data:image/png;base64,${pendingEnrollment.qr_code_base64}`}
                        alt={t.mfa.otp.qrAlt}
                    />
                    <div class="manualSecret">
                        <span>{t.mfa.otp.manualSecret}</span>
                        <code>{pendingEnrollment.secret_base32}</code>
                    </div>
                    {#if enrollmentSecs !== undefined}
                        <p class="expires" aria-live="polite">
                            {t.mfa.otp.expiresIn}
                            {enrollmentSecs}
                            {t.common.seconds}
                        </p>
                    {/if}
                </div>
            {:else}
                <p>{t.mfa.otp.activationCode}</p>
            {/if}
            <Form action="" onSubmit={handleActivateOtp}>
                <Input
                    bind:ref={refInput}
                    name="otp"
                    autocomplete="one-time-code"
                    label={t.mfa.otp.code}
                    placeholder={'0'.repeat(pendingCodeSize)}
                    maxLength={pendingCodeSize}
                    minLength={pendingCodeSize}
                    pattern={PATTERN_OTP_CODE}
                    bind:isError={isInputError}
                    required
                />
                <div class="regBtns">
                    <Button type="submit" isLoading={isOtpLoading}>{t.mfa.otp.verify}</Button>
                    <Button level={3} onclick={cancelOtpEnrollment}>{t.common.cancel}</Button>
                </div>
            </Form>
        {:else if showOtpRegistration}
            <Form action="" onSubmit={handleCreateOtp}>
                <fieldset class="otpKinds">
                    <legend>{t.mfa.otp.chooseKind}</legend>
                    <label>
                        <input type="radio" name="otp-kind" value="email" bind:group={otpKind} />
                        <span>
                            <b>{t.mfa.otp.titleEmail}</b>
                            <small>{t.mfa.otp.emailDescription}</small>
                        </span>
                    </label>
                    <label>
                        <input type="radio" name="otp-kind" value="time" bind:group={otpKind} />
                        <span>
                            <b>{t.mfa.otp.titleTime}</b>
                            <small>{t.mfa.otp.timeDescription}</small>
                        </span>
                    </label>
                </fieldset>
                <Input
                    name="otp-name"
                    bind:value={otpName}
                    autocomplete="off"
                    label={t.mfa.otp.factorName}
                    placeholder={t.mfa.otp.factorNamePlaceholder}
                    maxLength={32}
                    pattern={PATTERN_USER_NAME}
                    required={otpKind === 'time'}
                    bind:isError={isInputError}
                />
                <div class="regBtns">
                    <Button type="submit" isLoading={isOtpLoading}>{t.mfa.otp.continue}</Button>
                    <Button
                        level={3}
                        onclick={() => {
                            showOtpRegistration = false;
                            otpName = '';
                        }}>{t.common.cancel}</Button
                    >
                </div>
            </Form>
        {:else}
            <div class="button">
                <Button
                    level={hasOtp === false ? 1 : 2}
                    onclick={() => (showOtpRegistration = true)}>{t.mfa.registerNew}</Button
                >
            </div>
        {/if}

        {#if hasOtp}
            <div class="keysHeader">
                {t.mfa.registerdOtps}
            </div>
        {/if}
        <div class="keysContainer">
            {#each otps as otp (otp.id)}
                <UserOtp {otp} showInactive={false} onDelete={handleDeleteOtp} />
            {/each}
        </div>

        {#if hasOtp}
            <div class="button">
                <Button
                    onclick={() => {
                        mfaPurpose = 'Test';
                        mfaKind = 'otp';
                    }}>{t.mfa.test}</Button
                >
            </div>
        {/if}

        <div class:success={!err} class:err role={err ? 'alert' : 'status'} aria-live="polite">
            {msg}
        </div>
    {/if}
</div>

<Modal bind:showModal bind:closeModal>
    {#if user.webauthn_user_id}
        <p style:max-width="20rem">
            {t.mfa.reAuthenticatePasskey}
        </p>
        <ul>
            {#each passkeys as pk}
                <li>{pk.name}</li>
            {/each}
        </ul>

        <div style:margin-top="1rem">
            <Button bind:ref={refPkAuthBtn} onclick={onMfaTokenWebauthnSubmit}>
                {t.common.authenticate}
            </Button>
        </div>
    {:else if isOtpEnabled && hasOtp}
        <p style:max-width="20rem">
            {t.mfa.reAuthenticateOtp}
        </p>

        <ul>
            {#each otps as otp}
                <li>{otp.kind}</li>
            {/each}
        </ul>

        <div style:margin-top="1rem">
            <Button bind:ref={refPkAuthBtn} onclick={onMfaTokenOtpSubmit}>
                {t.common.authenticate}
            </Button>
        </div>
    {:else}
        <p style:max-width="20rem">
            {t.mfa.reAuthenticatePwd}
        </p>

        <Form action="" onSubmit={onMfaTokenSubmit}>
            <InputPassword
                bind:ref={refInput}
                name="password"
                autocomplete="current-password"
                label={t.account.passwordCurr}
                placeholder={t.account.passwordCurr}
                required
            />
            <Button type="submit" {isLoading}>{t.common.authenticate}</Button>
            {#if pwdErr}
                <div class="pwdInvalid">
                    {pwdErr}
                </div>
            {/if}
        </Form>
    {/if}
</Modal>

<style>
    p {
        margin: 0.5rem 0;
    }

    .btnRefresh {
        color: hsla(var(--text) / 0.5);
    }

    .container {
        display: flex;
        flex-direction: column;
        justify-content: flex-start;
        align-items: flex-start;
    }

    .button {
        margin-top: 0.33rem;
    }

    .keysContainer {
        width: 100%;
        max-height: 20rem;
        overflow-y: auto;
    }

    .keysHeader {
        margin-top: 0.5rem;
        font-weight: bold;
    }

    .modToken {
        display: flex;
        gap: 0.5rem;
    }

    .pwdInvalid {
        color: hsl(var(--error));
        margin: 0.5rem 0;
    }

    .success,
    .err {
        margin: 0.5rem -0.3rem;
        text-align: left;
    }

    .success {
        margin-left: 0.2rem;
        color: hsl(var(--action));
    }

    .timeLeft {
        color: hsl(var(--action));
    }

    .regBtns {
        margin: 0.25rem 0;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .regNewBtn {
        margin: 0.5rem 0;
    }

    .otpKinds {
        width: min(95dvw, 25rem);
        margin: 0.5rem 0;
        padding: 0;
        border: 0;
    }

    .otpKinds legend {
        margin-bottom: 0.25rem;
        font-weight: bold;
    }

    .otpKinds label {
        min-height: 2.75rem;
        display: flex;
        align-items: center;
        gap: 0.65rem;
        cursor: pointer;
    }

    .otpKinds input {
        width: 1.1rem;
        height: 1.1rem;
        margin: 0;
        accent-color: hsl(var(--action));
    }

    .otpKinds input:focus-visible {
        outline: 2px solid hsl(var(--accent));
        outline-offset: 2px;
    }

    .otpKinds span {
        display: flex;
        flex-direction: column;
    }

    .otpKinds small {
        color: hsla(var(--text) / 0.75);
    }

    .totpSetup {
        width: min(95dvw, 25rem);
    }

    .qrCode {
        width: min(15rem, 80dvw);
        height: auto;
        display: block;
        margin: 0.75rem auto;
        border-radius: var(--border-radius);
    }

    .manualSecret {
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
    }

    .manualSecret code {
        max-width: 100%;
        padding: 0.5rem;
        overflow-wrap: anywhere;
        border-radius: var(--border-radius);
        background: hsl(var(--bg-high));
        user-select: all;
    }

    .expires {
        color: hsla(var(--text) / 0.75);
    }
</style>
