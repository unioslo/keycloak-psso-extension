<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
<#if section = "title">
    ${msg("pssoBadgeTitle")}
<#elseif section = "header">
    ${msg("pssoBadgeTitle")}
<#elseif section = "form">

<form id="kc-badge-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">

    <#-- Filled in by psso-badge.js with whatever scanQR() decoded. -->
    <input type="hidden" id="badge" name="badge" value=""/>

    <div class="${properties.kcFormGroupClass!}">
        <p id="psso-badge-status" aria-live="polite">${msg("pssoBadgeInstruction")}</p>
    </div>

    <div class="${properties.kcFormGroupClass!}">
        <#-- type="button": this re-opens the camera, it does not post the form. -->
        <button type="button" id="psso-badge-rescan" style="display:none"
                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">
            ${msg("pssoBadgeScanAgain")}
        </button>
    </div>

    <div class="${properties.kcFormGroupClass!}">
        <#-- A named submit button: "fallback" is only sent when a person clicks it, never
             when the script submits the form programmatically. -->
        <button type="submit" id="psso-badge-fallback" name="fallback" value="1"
                class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">
            ${msg("pssoBadgeUsePassword")}
        </button>
    </div>

</form>

<#-- Localised strings for the scanner.
     ?js_string escapes for a JavaScript literal (including the "</script>" case).
     ?no_esc is then required because Keycloak renders every .ftl with
     HTMLOutputFormat: without it the auto-escaper would run over the result and a
     quote in a message would reach the browser as &quot;. -->
<script type="text/javascript">
    <#-- Only auto-open the camera on a clean render. If the server came back with an
         error the previous scan was rejected, and silently rescanning would loop a pupil
         into a brute-force lockout with nobody noticing. Wait for a deliberate click. -->
    window.pssoBadgeAutoScan = <#if message?has_content && message.type == 'error'>false<#else>true</#if>;

    window.pssoBadgeMessages = {
        scanning:    "${msg("pssoBadgeScanning")?js_string?no_esc}",
        unrecognised:"${msg("pssoBadgeUnrecognised")?js_string?no_esc}",
        noCamera:    "${msg("pssoBadgeNoCamera")?js_string?no_esc}",
        cancelled:   "${msg("pssoBadgeCancelled")?js_string?no_esc}",
        timeout:     "${msg("pssoBadgeTimeout")?js_string?no_esc}",
        error:       "${msg("pssoBadgeError")?js_string?no_esc}",
        retry:       "${msg("pssoBadgeRetry")?js_string?no_esc}"
    };
</script>
<script type="text/javascript" src="${url.resourcesPath}/js/psso-badge.js"></script>

</#if>
</@layout.registrationLayout>
