# Keycloak Platform Single Sign-on Extension

This is a Keycloak extension that makes it compliant with [Apple Platform Single Sign-on for macOS](https://support.apple.com/en-ca/guide/deployment/dep7bbb05313/web).

## Features

- Provides device attestation so that only requests from enrolled macOS devices are accepted
- Allows revocation of user registration on GUI, both for users and administrators

![User registration is trated as a credential on Keycloak. The user (and administrators) can see and managem them.](https://github.com/user-attachments/assets/8d94bd8c-66a2-4cd3-ba9e-6f29a0254e54)


## Known limitations

- **Secure Enclave-only**: this extension only implements the Secure Enclave authentication method. 
- **Fixed client**: to use this extension, you need to create a client called _psso_. In the future we will make this configurable. The client needs to be public and it needs to include the `urn:apple:platformsso` scope.
- **Revoke Refresh Token needs to be off**: the refresh token is used for login, as it is used as an opaque token to authenticate and identify the user. In the future we might change this. This is the default option in Keycloak.
- **No UI or API for managing devices**: Currently, devices can only be enrolled. An API will be added for integration with MDMs so that the lifecycle of a device can include removing them from Keycloak.

## How to use it

Download the package - a _jar_ file, and move it to the _providers_ folder of your Keycloak installation.

Or build this with Maven:

```
$ mvn clean install
```
Device and user registrations require a valid Access Token from the user. Our companion SSO extension provides that authentication.


## Companion SSO Extension: Weblogin SSO

We also developed a companion SSO Extension called _Weblogin SSO_, which is a bit limited in certain situations. 

You can check the SSO Extension here: https://github.com/unioslo/weblogin-mac-sso-extension


## Documentation

We haven't documented this extension throughly yet, but you can find a bit of explanation about the endpoints on this article: https://francisaugusto.com/2025/Platform_single_sign_on_diy/


## Discussions

It would be very nice if other developers could join our efforts, especially when it comes to the SSO Extension and its processing of SAML flows. If you can and want to help, send PR’s our way or drop as a line on the #Keycloak channel at the MacAdmins [Slack](https://macadmins.slack.com/archives/C09UKEDGBEH) 


## Acknowledgement

Thanks to Timothy Perfitt from [Twocanoes](https://twocanoes.com) for the inspiration provided with their tutorials and code regarding SSO Extensions. His [psso-server-go](https://github.com/twocanoes/psso-server-go) was particularly useful to understand a few concepts regarding user and device registration.
