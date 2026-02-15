# OAuth 2.0 Authentication Vulnerabilities

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)


## Overview

OAuth 2.0 is a widely used framework for authorization that enables users to grant third-party applications limited access to their resources without exposing login credentials. While powerful and popular, OAuth 2.0 is prone to implementation errors, leading to vulnerabilities such as sensitive data leakage and authentication bypass.

<img width="1054" height="400" alt="image" src="https://github.com/user-attachments/assets/21223bfa-eb60-4c74-b333-9ba76fff8261" />


## What is OAuth?

OAuth enables websites and apps to request limited access to a user's account on another platform (e.g., Google, Facebook). It does so without the user revealing their login credentials to the requesting site.

Use cases include:

* Accessing a user’s contact list to suggest friends
* Logging into a service using a third-party account

> Note: OAuth 2.0 is the standard. OAuth 1.0a is obsolete and very different.

## How OAuth 2.0 Works

OAuth involves the following parties:

* **Client application** – The app requesting data access
* **Resource owner** – The user who owns the data
* **OAuth provider** – Hosts the data and the OAuth service (authorization + resource server)

OAuth uses different "flows" (grant types) depending on the context. The two main ones are:

* **Authorization Code Grant**
* **Implicit Grant**

### General OAuth Steps

1. Client app requests access to specific user data.
2. User logs in and consents.
3. Client receives an **access token**.
4. Client uses token to access resources.

## OAuth Grant Types

### Authorization Code Grant (Most Secure)



<img width="882" height="626" alt="image" src="https://github.com/user-attachments/assets/a48d59b5-7c7d-4d15-ab75-242aa49601a1" />


1. **Authorization Request**

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=xyz HTTP/1.1
Host: oauth-authorization-server.com
```

2. **User Login & Consent** – User logs in and approves scopes (e.g., `openid`, `profile`).

3. **Authorization Code Redirect**

```http
GET /callback?code=abc123&state=xyz HTTP/1.1
Host: client-app.com
```

4. **Access Token Request (server-to-server)**

```http
POST /token HTTP/1.1
Host: oauth-authorization-server.com
...
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=abc123
```

5. **Token Response**

```json
{
  "access_token": "z0y9x8w7v6u5",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile"
}
```

6. **API Call**

```http
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5
```

7. **User Data Response**

```json
{
  "username": "carlos",
  "email": "carlos@carlos-montoya.net"
}
```

### Implicit Grant (Less Secure)

<img width="875" height="526" alt="image" src="https://github.com/user-attachments/assets/a7626b6a-04da-40bd-9703-708d51e12f39" />


Best for SPAs and desktop apps.

1. **Authorization Request** (Note `response_type=token`)

```http
GET /authorization?...&response_type=token&...
```

2. **User Login & Consent**
3. **Access Token in Fragment**

```http
GET /callback#access_token=...&token_type=Bearer&...
```

4. **Extract Token via JavaScript and use in API Call**

## OAuth Scopes

Scopes define the specific data or actions the client is requesting.
Examples:

* `scope=contacts`
* `scope=openid profile` (OpenID Connect)

## OAuth Authentication

OAuth is now often used for authentication (SSO-like). Typical flow:

1. User chooses “Log in with social media.”
2. Client app requests basic identity data via OAuth.
3. App uses the data to authenticate the user and start a session.

## Key Takeaways

* **Authorization Code Grant** is more secure than Implicit Grant.
* **Validate `redirect_uri` and `state`** parameters to prevent redirection and CSRF attacks.
* Always use HTTPS and secure back-channels for server-to-server communication.
* Regularly audit OAuth configuration and permissions.

---

**Further Reading:**

* [Hidden OAuth Attack Vectors (PortSwigger)](https://portswigger.net/research/hidden-oauth-attack-vectors)
* [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
* [OpenID Connect](https://openid.net/connect/)
