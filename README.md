*Important:* If you or your institution are using this extension, please send a PR with the name of your institution under the file ["Who uses this.md"](https://github.com/unioslo/keycloak-psso-extension/blob/main/Who%20uses%20this.md). This helps us to prioritize agnostic development of this extension.

# Keycloak Platform Single Sign-on Extension

This is a Keycloak extension that makes it compliant with [Apple Platform Single Sign-on for macOS](https://support.apple.com/en-ca/guide/deployment/dep7bbb05313/web).

## Features

- Provides device attestation so that only requests from enrolled macOS devices are accepted
- Allows revocation of user registration on GUI, both for users and administrators
- Use a registration token for MDM verification

![User registration is trated as a credential on Keycloak when using the Secure Enclave keys. The user (and administrators) can see and managem them.](https://github.com/user-attachments/assets/8d94bd8c-66a2-4cd3-ba9e-6f29a0254e54)


## Requirements

- Keycloak 26.5 or newer
- Keycloak must use Postgresql or MariaDB for database. If you use something else, 
please open an issue and we will try to implement it. Or add the scheme yourself to the changelog files.
- The "Declarative-ui" feature of Keycloak needs to be enabled

## Known limitations

- **Fixed client**: to use this extension, you need to create a client called _psso_. In the future we will make this configurable. The client needs to be public and it needs to include the `urn:apple:platformsso` scope.
- **Revoke Refresh Token needs to be off**: the refresh token is used for login, as it is used as an opaque token to authenticate and identify the user. In the future we might change this. This is the default option in Keycloak.
- **No UI for managing devices**: Currently, devices can only be managed via API. Use our device API for integration with MDMs so that the lifecycle of a device can include removing them from Keycloak.

## How to use it

Download the package - a _jar_ file, and move it to the _providers_ folder of your Keycloak installation.

Or build this with Maven:

```
$ mvn clean install
```
Device and user registrations require a valid Access Token from the user. Our companion SSO extension provides that authentication.


## Verifying a release

Every release ships the jar together with a SHA-256 checksum and an SSH signature
over that checksum. The signature is made with the same key that signs the commits
of this repository, so you can cross-check it against the _Verified_ badge GitHub
shows on our commits. The public key is in [`allowed_signers`](allowed_signers) and
is also served, independently of this repository, at
https://api.github.com/users/oculos/ssh_signing_keys

Download the three release assets plus the key, then:

```
$ shasum -a 256 -c keycloak-psso.jar.sha256
keycloak-psso.jar: OK

$ ssh-keygen -Y verify -f allowed_signers -I franciaa@uio.no \
    -n file -s keycloak-psso.jar.sha256.sig < keycloak-psso.jar.sha256
Good "file" signature for franciaa@uio.no with RSA key SHA256:rSbAcdqbMIYLHmnh+0xocKuxBpAmTJbwTCd8yeJKk2E
```

Both commands must succeed. The first proves the jar matches the checksum, the
second proves the checksum was signed by us. `-n file` is a namespace label, not a
filename — it has to match exactly or verification fails.


## Companion SSO Extension: Weblogin SSO

We also developed a companion SSO Extension called _Weblogin SSO_, which is a bit limited in certain situations. 

You can check the SSO Extension here: https://github.com/unioslo/weblogin-mac-sso-extension


## Documentation

There is a small documentation on how to use this extension on 
the wiki section of this repo: https://github.com/unioslo/keycloak-psso-extension/wiki

You can also find a bit of explanation about the endpoints 
on this article: https://francisaugusto.com/2025/Platform_single_sign_on_diy/ .
The purpose of this article is mostly to help developers on how to adapt our SSO Extension or this extension.


## Discussions and mailing list

It would be very nice if other developers could join our efforts, especially when it comes to the SSO Extension and its processing of SAML flows. If you can and want to help, send PR’s our way or drop as a line on the #Keycloak channel at the MacAdmins [Slack](https://macadmins.slack.com/archives/C09UKEDGBEH) 

Please subscribe to our mailing list for discussions and announcements: https://sympa.uio.no/usit.uio.no/admin/keycloak-psso



## Acknowledgement

Thanks to Timothy Perfitt from [Twocanoes](https://twocanoes.com) for the inspiration provided with their tutorials and code regarding SSO Extensions. His [psso-server-go](https://github.com/twocanoes/psso-server-go) was particularly useful to understand a few concepts regarding user and device registration.
