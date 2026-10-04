<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
<#if section = "title">
${msg("loginTitle",realm.name)}
<#elseif section = "header">
    ${msg("loginTitleHtml",realm.name)}
<#elseif section = "form">

<form id="stepupForm" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" >

    <input type="hidden" id="signedtoken" name="signedtoken" value="">
    <input type="hidden" id="reauthenticate" name="reauthenticate" value="">
    <#-- The signed step-up token, NOT the raw challenge: the extension verifies this
         against the realm JWKS and only then reads the reauth_challenge claim out of it. -->
    <input type="hidden" id="stepUpToken" name="stepUpToken" value="${stepUpToken}">

</form>

<script>
    pssoStepUp();


    function pssoStepUp() {
        const stepUpToken = document.getElementById("stepUpToken").value;
        // Send message to native SSO extension. The "challenge" key carries the
        // signed step-up token, not the challenge value itself.
        window.webkit.messageHandlers.pssoStepUp.postMessage({
            type: "getSignedToken",
            challenge: stepUpToken
        });
    }

    // Called by native code after signature
    function pssoSigned(signedToken) {
        document.getElementById("signedtoken").value = signedToken;
        document.getElementById("stepupForm").submit();

    }
</script>
</#if>
</@layout.registrationLayout>