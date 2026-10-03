/* Copyright 2025 University of Oslo, Norway
 * This file is part of the Keycloak Platform SSO Extension codebase.
 *
 * QR badge scanner for Platform SSO web-based authentication.
 *
 * There is no QR decoding library here on purpose. window.apple.platformSSO.scanQR() does
 * camera access and decoding natively, in a secure system process, and resolves with the
 * decoded string - so no jsQR, no ZXing, no getUserMedia.
 */
(function () {
    "use strict";

    var PREFIX = "PSSO1.";

    var MSG = window.pssoBadgeMessages || {};
    // Set by the template from the server's own view of whether this render carries an
    // error. More reliable than anything the page could remember for itself: it is right
    // on a first visit, after a failure, and after a successful login alike.
    var AUTO_SCAN = window.pssoBadgeAutoScan !== false;

    function sso() {
        return (window.apple && window.apple.platformSSO) || null;
    }

    function status(text) {
        var el = document.getElementById("psso-badge-status");
        if (el && text) {
            el.textContent = text;
        }
    }

    function showRescan(text) {
        status(text);
        var btn = document.getElementById("psso-badge-rescan");
        if (btn) {
            btn.style.display = "";
            btn.focus();
        }
    }

    // For the one rejection that scanning again cannot fix. Offering "Scan again" here
    // would contradict the message, which already says to use a password.
    function showNoRescan(text) {
        status(text);
        var btn = document.getElementById("psso-badge-rescan");
        if (btn) {
            btn.style.display = "none";
        }
        var fallback = document.getElementById("psso-badge-fallback");
        if (fallback) {
            fallback.focus();
        }
    }

    function b64urlDecode(s) {
        s = s.replace(/-/g, "+").replace(/_/g, "/");
        while (s.length % 4) {
            s += "=";
        }
        var bin = atob(s);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) {
            bytes[i] = bin.charCodeAt(i);
        }
        // atob yields Latin-1. Without this, any aa/ae/oe in the payload would corrupt.
        return new TextDecoder("utf-8").decode(bytes);
    }

    function wellFormed(raw) {
        if (typeof raw !== "string" || raw.lastIndexOf(PREFIX, 0) !== 0) {
            return false;
        }
        try {
            var o = JSON.parse(b64urlDecode(raw.slice(PREFIX.length)));
            // Shape check only - validating the badge is the server's job.
            return !!(o && o.u && o.t);
        } catch (e) {
            return false;
        }
    }

    function submit(raw) {
        var form = document.getElementById("kc-badge-form");
        var field = document.getElementById("badge");
        if (!form || !field) {
            return;
        }
        field.value = raw;
        // requestSubmit() fires the submit event and any inline onsubmit; form.submit()
        // does not, and submitting without a submitter keeps "fallback" out of the POST.
        if (form.requestSubmit) {
            form.requestSubmit();
        } else {
            form.submit();
        }
    }

    function scan() {
        var api = sso();
        if (!api || typeof api.scanQR !== "function") {
            return;
        }
        var btn = document.getElementById("psso-badge-rescan");
        if (btn) {
            btn.style.display = "none";
        }
        status(MSG.scanning);

        api.scanQR().then(function (data) {
            if (wellFormed(data)) {
                submit(data);
            } else {
                showRescan(MSG.unrecognised);
            }
        }).catch(function (err) {
            // cancelled | error | invalid | timeout | unavailable
            var reason = (err && err.message) || "error";
            if (reason === "unavailable") {
                // Not recoverable by scanning again: point at the password button instead.
                showNoRescan(MSG.noCamera);
            } else if (reason === "cancelled") {
                showRescan(MSG.cancelled);
            } else if (reason === "timeout") {
                showRescan(MSG.timeout);
            } else {
                showRescan(MSG.error);
            }
        });
    }

    function start() {
        var btn = document.getElementById("psso-badge-rescan");

        if (!sso()) {
            // An ordinary browser. Stay inert and leave the password link as the way out.
            return;
        }

        if (btn) {
            btn.addEventListener("click", scan);
        }

        if (!AUTO_SCAN) {
            // The server rejected the last scan. Offer the button; do not reopen the
            // camera by ourselves.
            showRescan(MSG.retry);
            return;
        }

        scan();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }
})();
