<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
<#if section = "title">
${msg("loginTitle",realm.name)}
<#elseif section = "header">
    ${msg("loginTitleHtml",realm.name)}
<#elseif section = "form">

<form id="stepupForm" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" >

    <input type="hidden" id="signedtoken" name="signedtoken" value="">
</form>

<script>
    pssoStepUp();


    function pssoStepUp() {
       // const challenge = document.getElementById("challenge").value;

        // Send message to native SSO extension
        window.webkit.messageHandlers.pssoStepUp.postMessage({
            type: "getSignedToken",
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