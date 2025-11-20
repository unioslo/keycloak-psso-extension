# keycloak-psso-extension

This is a Keycloak extension that makes Keycloak compliant with [Apple Platform Single Sign-on for macOS](https://support.apple.com/en-ca/guide/deployment/dep7bbb05313/web).

## Features

- Provides device attestation so that only requests from enrolled macOS devices are accepted
- Allows revocation of user registration on GUI, both for users and administrators

![User registration is trated as a credential on Keycloak. The user (and administrators) can see and managem them.](https://github.com/user-attachments/assets/8d94bd8c-66a2-4cd3-ba9e-6f29a0254e54)


## Known limitations

- **Secure Enclave-only**: this extension only implements the Secure Enclave authentication method. 
- **Fixed client**: to use this extension, you need to create a client called _psso_. In the future we will make this configurable. The client needs to be public and it needs to include the `urn:apple:platformsso` scope.
- **Revoke Refresh Token needs to be off**: the refresh token is used for login, as it is used as an opaque token to authenticate and identify the user. In the future we might change this. This is the default option in Keycloak.
- **Missing ACR/LoA and other checks**: If you use ACS/LoA, there are no checks on this authenticator. It will be implemented.
- **Might be incompatible with the _Organizations_ feature**: We based our Authenticator on the Cookies Authenticator, which does a series of checks, including organization checks. These are not implemented here yet.

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


## Acknowledgement

Thanks to Timothy Perfitt from [Twocanoes](https://twocanoes.com) for the inspiration provided with their tutorials and code regarding SSO Extensions. His [psso-server-go](https://github.com/twocanoes/psso-server-go) was particularly useful to understand a few concepts regarding user and device registration.
