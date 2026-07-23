<script lang="ts">
    import { useI18n } from '$state/i18n.svelte';
    import { onMount } from 'svelte';
    import Loading from './Loading.svelte';
    import type { MfaPurpose } from '$api/types/mfa';
    import type {
        OtpAdditionalData,
        OtpAuthFinishResult,
        OtpAuthStartResult,
    } from '$mfa/otp/types';
    import { otpAuthFinish, otpAuthStart } from '$mfa/otp/authentication';
    import Input from './form/Input.svelte';
    import { TPL_OTP_LENGTH } from '$utils/constants';
    import Template from './Template.svelte';
    import Form from './form/Form.svelte';
    import Button from './button/Button.svelte';
    import type { ActiveOtp } from '$api/types/authorize';
    import type { OtpResponse } from '$api/types/otp';
    import type { OtpKind } from '$api/types/otp';

    let {
        activeOtps,
        purpose,
        selectedOtpId,
        selectedOtpKind,
        onError,
        onSuccess,
    }: {
        activeOtps: ActiveOtp[] | OtpResponse[];
        purpose: MfaPurpose;
        selectedOtpId?: string;
        selectedOtpKind?: OtpKind;
        onError: (error: string) => void;
        onSuccess: (res?: OtpAdditionalData) => void;
    } = $props();

    let t = useI18n();
    let refInput: undefined | HTMLInputElement = $state();
    let isInputError = $state(false);
    let isFinishing = $state(false);
    let otpKind: undefined | OtpKind = $state();

    let otpSize = $state(6);
    let codeSize = $derived(otpKind === 'time' ? 6 : otpSize);
    let codePattern = $derived(`^[0-9]{${codeSize}}$`);

    let otpStartRes: undefined | OtpAuthStartResult = $state();
    let otpFinishRes: undefined | OtpAuthFinishResult = $state();

    onMount(async () => {
        if (
            selectedOtpKind === 'time' &&
            !activeOtps.some(otp => ('otp_kind' in otp ? otp.otp_kind : otp.kind) === 'time')
        ) {
            onError('No active authenticator app is available');
            return;
        }
        let selected = activeOtps.find(otp => {
            let id = 'otp_id' in otp ? otp.otp_id : otp.id;
            let kind = 'otp_kind' in otp ? otp.otp_kind : otp.kind;
            return (
                (!selectedOtpId || id === selectedOtpId) &&
                (!selectedOtpKind || kind === selectedOtpKind)
            );
        });
        if (!selected) {
            onError('No matching one-time password method is available');
            return;
        }
        let otpId = 'otp_id' in selected ? selected.otp_id : selected.id;
        otpKind = 'otp_kind' in selected ? selected.otp_kind : selected.kind;
        otpStartRes = await otpAuthStart(otpId, purpose);
    });

    $effect(() => {
        if (otpStartRes) {
            if (otpStartRes.error) {
                setTimeout(() => {
                    onError(otpStartRes?.error || 'OTP Error');
                }, 3000);
            }
        }
    });

    $effect(() => {
        if (otpFinishRes) {
            if (otpFinishRes.error) {
                setTimeout(() => {
                    onError(otpFinishRes?.error || 'OTP Error');
                }, 3000);
            } else {
                onSuccess(otpFinishRes.data);
            }
        }
    });

    $effect(() => {
        refInput?.focus();
    });

    async function onLoginOtpSubmit(_form: HTMLFormElement, params: URLSearchParams) {
        let otpCode = params.get('otp');
        if (otpStartRes && otpStartRes.data && otpCode) {
            isFinishing = true;
            otpFinishRes = await otpAuthFinish(otpStartRes.data.code, otpCode);
            isFinishing = false;
        }
    }
</script>

<Template id={TPL_OTP_LENGTH} bind:value={otpSize} />

{#if purpose}
    <div class="wrapperOuter">
        <div class="wrapperInner">
            <div class="content">
                <div class="contentRow">
                    <div class="contentHeader">
                        {t.authorize.expectingOtp}
                    </div>
                </div>

                <div class="contentRow">
                    <div>
                        {#if !otpStartRes}
                            <Loading />
                        {/if}
                    </div>
                </div>

                <div class="contentRow">
                    {#if otpStartRes}
                        {#if otpStartRes.error}
                            <div class="err">
                                {otpStartRes.error}
                            </div>
                        {:else}
                            <div class="good">
                                <p>
                                    {otpKind === 'time'
                                        ? t.mfa.otp.loginTime
                                        : t.mfa.otp.loginEmail}
                                </p>
                                <Form action="" onSubmit={onLoginOtpSubmit}>
                                    <Input
                                        bind:ref={refInput}
                                        name="otp"
                                        autocomplete="one-time-code"
                                        label={t.mfa.otp.code}
                                        placeholder={'0'.repeat(codeSize)}
                                        maxLength={codeSize}
                                        minLength={codeSize}
                                        pattern={codePattern}
                                        bind:isError={isInputError}
                                        required
                                    />
                                    <Button type="submit" isLoading={isFinishing}
                                        >{t.mfa.otp.verify}</Button
                                    >
                                </Form>
                            </div>
                        {/if}
                    {/if}
                </div>
            </div>
        </div>
    </div>
{/if}

<style>
    .content {
        padding: 1rem;
        border: 1px solid hsl(var(--bg-high));
        border-radius: var(--border-radius);
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        color: hsl(var(--text-high));
        text-align: center;
        z-index: 99;
        background: hsla(var(--bg) / 0.9);
    }

    .contentRow {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        margin: 0.25em;
    }

    .contentHeader {
        margin-bottom: 0.2em;
        font-weight: bold;
    }

    .err,
    .good {
        font-weight: bold;
    }

    .good {
        color: hsl(var(--action));
    }

    /*.muted {*/
    /*    color: hsla(var(--text) / .8)*/
    /*}*/

    /*progress {*/
    /*    accent-color: hsl(var(--accent));*/
    /*}*/

    .wrapperOuter {
        position: absolute;
        top: 0;
        left: 0;
    }

    .wrapperInner {
        width: 100vw;
        height: 100vh;
        position: relative;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        background: rgba(0, 0, 0, 0.85);
        z-index: 20;
    }
</style>
