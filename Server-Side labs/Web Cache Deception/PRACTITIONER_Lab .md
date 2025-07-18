## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Web Cache Deception**:

**Exploiting path delimiters for web cache deception**  
This lab demonstrates how attackers can abuse path delimiter variations to trick caches into storing sensitive content.

**Exploiting origin server normalization for web cache deception**  
This lab shows how mismatches in URL normalization between cache and origin servers can be exploited.

**Exploiting cache server normalization for web cache deception**  
This lab covers techniques to exploit cache server normalization issues to achieve web cache deception.

---

### LAB 2 - Exploiting path delimiters for web cache deception

### Lab Description

![image](https://github.com/user-attachments/assets/bd95fe48-98e4-41d2-b70a-ccff4ad363b3)


You're right — thanks for pointing that out! Here's the **updated professional overview section** with **delimiter discrepancies**, **delimiter decoding discrepancies**, and **framework behavior** all incorporated:

---

## Overview: Delimiter Discrepancies and Web Cache Deception

Delimiter discrepancies arise when the **origin server** and the **cache server** interpret special characters in URL paths differently. These mismatches can allow an attacker to **append fake static extensions** (e.g., `.css`, `.js`, `.ico`) to dynamic endpoints and trick the cache into storing **private, user-specific content**.

Many web frameworks interpret delimiters in unique ways:

* `;` is used for matrix parameters in **Java Spring**.
* `.` denotes response format in **Ruby on Rails**.
* `%00` (null byte) is treated as a terminator in **OpenLiteSpeed**.

In contrast, most caching layers (CDNs, proxies) treat these characters **literally** as part of the file path. This allows attackers to:

1. Forge a URL like `/account;extra.css` or `/user.json`, which the origin server ignores or truncates.
2. The **origin server** returns dynamic data (e.g., a user's profile).
3. The **cache server**, seeing the fake static extension, caches the response as if it were a static resource.

For example:

```
/profile;foo.css → origin returns profile info (ignores `;foo.css`), cache stores it under `.css`
```

---

## Delimiter Decoding Discrepancies

A second layer of this vulnerability arises when **encoded delimiters** like `%23` (URL-encoded `#`) or `%3F` (`?`) are **decoded by the origin but not by the cache**, or vice versa. This can cause further inconsistency in how the path is parsed.

Example:

```
/profile%23wcd.css
→ Cache sees: /profile%23wcd.css (matches `.css` rule)
→ Origin decodes %23 to `#`, interprets path as `/profile`
```

Similarly:

```
/myaccount%3fwcd.css
→ Cache applies `.css` rule to encoded path
→ Then decodes `%3F` → `?` before forwarding
→ Origin sees `/myaccount?wcd.css` and ignores query
```

These decoding mismatches are often framework- and cache-specific. Some caches decode before matching cache rules, while others decode after. This behavior enables attackers to inject misleading extensions without detection.

---

## Exploiting These Behaviors

To identify and exploit delimiter-based vulnerabilities:

* Use **Burp Suite** and **Intruder** to test common delimiters (`;`, `.`, `!`, `%00`, etc.)
* Test both **raw** and **encoded** forms of delimiters (`;` vs `%3B`, `?` vs `%3F`)
* Observe differences in server behavior, response headers (e.g., `X-Cache`), and response content

If the cache stores a dynamic response under a crafted path — and the origin server ignores the added part — you’ve successfully triggered **Web Cache Deception**.

Let me know if you'd like this incorporated into your `.md` file or published on GitHub with your previous write-ups.


### Solution

Before starting, configure FoxyProxy to intercept requests through Burp Suite. Ensure that ‘Intercept’ is turned off in Burp Suite while FoxyProxy is active, so that all requests are logged in the HTTP history. Then, log in to the application using the credentials **wiener:peter**.

Please note that the response will include your API key.

![image](https://github.com/user-attachments/assets/94d8aa76-292b-4e66-9656-c7af5fc545a2)

Go to Burpuite **Proxy > HTTP** history, **right-click** the `GET /my-account` request and select Send to Repeater.

![image](https://github.com/user-attachments/assets/a61315fa-15f0-40fd-8618-8d91d0eed97b)

Go to the Repeater tab and modify the path by adding an arbitrary segment. For example, change the path to `/my-account/abc`. Send the request and observe the **404** Not Found response without any evidence of caching. This indicates that the origin server does not abstract the path to `/my-account`.

![image](https://github.com/user-attachments/assets/cba05710-fe19-43f2-b8cb-9b6842760779)

Next, remove the arbitrary segment and append an arbitrary string to the original path. For instance, update the path to `/my-accountabc`. Send the request and note the **404** Not Found response with no signs of caching. This response will serve as a reference for identifying characters that are not used as delimiters.

![image](https://github.com/user-attachments/assets/e2026f55-157e-4502-be8f-d62a9bf19e3a)

Right-click the request and select **“Send to Intruder”** In the Intruder tab, ensure the Sniper attack type is selected and set a payload position after `/my-account` as follows: `/my-account§§abc`.

![image](https://github.com/user-attachments/assets/d9490ea4-5a20-4ff8-8f68-20b4cfa8cb8e)

Paste the delimiter payload list from [PortSwigger’s official lab](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list) into Burp Intruder’s payload positions for systematic testing.

![image](https://github.com/user-attachments/assets/18fd7ddd-7c05-4269-9a7a-4191889cc960)

Under **Payload encoding**, deselect **URL-encode** these characters.

![image](https://github.com/user-attachments/assets/34350a63-4f9b-49ce-98b7-f34fb4b1988e)

After the attack completes, review the results. You should find that the `;` and `?` characters return a 200 response with your API key, while other characters return a **404** Not Found response. This suggests that the origin server uses `;` and `?` as path delimiters.

![image](https://github.com/user-attachments/assets/4ef5c644-ed0c-437a-91fa-6b75faa49c8e)

Go back to the Repeater tab containing the /my-accountabc request. Add a `?` character after `/my-account` and append a static file extension to the path, such as `/my-account?abc.js`. Send the request and observe that the response does not indicate caching. This suggests that the cache also uses `?` as a path delimiter.

![image](https://github.com/user-attachments/assets/43705e23-55cd-4e82-86e0-e9a1696741cb)

In Burp’s browser, click “Go to exploit server.” In the Body section, craft an exploit to redirect the victim user, Carlos, to the malicious URL you crafted earlier. Make sure to update the arbitrary string to create a unique cache key, so Carlos’s account details are cached instead of the previously cached response:

```
<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account;hanzala.js"</script>

```

![image](https://github.com/user-attachments/assets/4f3d2b87-1726-4d8a-b4a2-1c5a46498a2e)

Store and click “Deliver exploit to victim.” When Carlos views the exploit, the response they receive will be stored in the cache.

Return to the Repeater tab, resend the request, and retrieve the response, which should now include Carlos’s API key. Copy the key.

![image](https://github.com/user-attachments/assets/35a85ccd-f204-44f1-a807-fbe7280ecf15)

Submit it to complete the lab.

![image](https://github.com/user-attachments/assets/ff895cd1-2748-4283-855c-bdd032904b58)


---

### LAB 3 - Exploiting origin server normalization for web cache deception

### Lab Description


![image](https://github.com/user-attachments/assets/3b815827-987e-4604-b53f-7d6382905e6b)


## Overview: Static Directory Rules and Path Normalization Discrepancies

**Static directory cache rules** are common configurations where web caches store resources under path prefixes like `/static`, `/assets`, or `/scripts`. These directories usually serve static content such as images, scripts, or stylesheets. However, if there's a discrepancy between how the **origin server** and the **cache server** **normalize URL paths**, this setup can become vulnerable to **Web Cache Deception**.

The root cause lies in **path normalization**, where URLs are standardized by decoding encoded characters and resolving dot-segments (e.g., `../`). If the origin server and cache server normalize paths differently, an attacker can construct a **path traversal payload** that bypasses cache rules and exposes sensitive content.

### Example:

```
/static/..%2fprofile  
→ Cache sees: /static/..%2fprofile (matches static directory rule)  
→ Origin resolves to: /profile (returns sensitive user data)  
→ Cached under static path
```

By placing traversal sequences like `..%2f` inside a "safe" static path, an attacker can:

1. **Bypass access controls** enforced by static cache directories.
2. **Trick the cache** into storing private responses under a path that looks harmless.
3. **Retrieve the cached response** by simply visiting the crafted static-path URL.

Identifying this vulnerability requires careful testing of how both the origin server and cache behave during normalization. Using tools like **Burp Suite**, **HTTP history analysis**, and **MIME-type filtering**, you can detect inconsistencies in dot-segment resolution and slash decoding that enable exploitation.


### Solution


Before starting, configure FoxyProxy to intercept requests through Burp Suite. Ensure that ‘Intercept’ is turned off in Burp Suite while FoxyProxy is active, so that all requests are logged in the HTTP history. Then, log in to the application using the credentials wiener:peter.

Please note that the response will include your API key.

![image](https://github.com/user-attachments/assets/516ebcad-7a08-47eb-a165-be60f038f2d7)

In the **Proxy > HTTP History** section, observe that the paths for static resources consistently begin with the directory prefix `/resources`. Additionally, note that responses to requests containing the `/resources` prefix exhibit signs of caching. Right-click on a request with the `/resources` prefix and select "Send to Repeater."

![image](https://github.com/user-attachments/assets/af6154f5-913a-4eed-83f9-27cadf02815f)

In Repeater, append an encoded dot-segment to the `/resources` path prefix, for example, `/resources/..%2fRESOURCES`. Send the request and observe that the 404 response includes the `X-Cache: miss header`.

![image](https://github.com/user-attachments/assets/1c935974-79d9-4022-9303-c129d1212400)

Resend the request and note that the value of the `X-Cache header` changes to `hit`. This may suggest that the cache does not decode or resolve the dot-segment, instead applying a cache rule based on the `/resources` prefix

![image](https://github.com/user-attachments/assets/7feaccd7-5131-446e-abe2-e6765d5f95b6)

Change the request to `/aaa/..%2fmy-account`. Attempt to construct an exploit by using the path `/resources/..%2fmy-account` and send the request. Note that this results in a 200 response containing your API key and the `X-Cache: miss` header.

![image](https://github.com/user-attachments/assets/4677cc79-8d39-471a-ad48-b3d3fae49489)

Resend the request to observe that the `X-Cache header` value updates to `hit`.

![image](https://github.com/user-attachments/assets/a3536c13-afed-4387-a046-42fcfc33a765)

In Burp Suite’s browser, click **“Go to exploit server.”** In the Body section, craft an exploit designed to navigate the victim user, Carlos, to a malicious URL. Ensure to include an arbitrary parameter as a cache buster so the victim does not receive the previously cached response:

```

<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/resources/..%2fmy-account"</script>

```

![image](https://github.com/user-attachments/assets/d68fb152-f190-487a-b98d-5bea204fbead)


Click **“Deliver exploit to victim.”** When Carlos views the exploit, the response is stored in the cache.

Visit the URL you delivered to Carlos in your exploit. If you have used Burp Suite for navigation, ensure to check the response to confirm that it includes the API key for user Carlos.

```

https://YOUR-LAB-ID.web-security-academy.net/resources/..%2fmy-account

```
![image](https://github.com/user-attachments/assets/15832a16-a7f4-4eb1-a45a-c299ea272d31)


Observe that the response includes the API key for user Carlos. Copy this key, click `“Submit solution,”` and then submit the API key to complete the lab.

![image](https://github.com/user-attachments/assets/a864d670-e78b-4ce8-bcb9-127d84fb8c2c)

---

### LAB 4 - Exploiting cache server normalization for web cache deception

### Lab Description

![image](https://github.com/user-attachments/assets/101cf7b5-0785-42a7-a336-785a24ce8928)


## Overview: Cache-Side Normalization Discrepancies

When the **cache server** normalizes paths differently from the **origin server**, particularly by resolving **encoded dot-segments**, it can lead to exploitable discrepancies. Specifically, if the cache decodes sequences like `%2f%2e%2e%2f` (i.e., `/../`) but the origin server treats them as literal text, an attacker can manipulate request paths to **trick the cache into storing sensitive content** under a static directory.

This technique leverages two components:

1. **Cache normalization**: The cache resolves encoded traversal sequences and maps the request to a static directory (e.g., `/static`).
2. **Origin delimiter truncation**: The origin server interprets a delimiter (e.g., `;`, `?`, `%00`) and **truncates the path**, returning sensitive dynamic content.

### Exploit Flow Example:

```
/profile;%2f%2e%2e%2fstatic  
→ Cache resolves to: /static (stores response)  
→ Origin server truncates at `;` and processes /profile (returns dynamic content)
```

In this setup:

* The **cache** sees a request to a static resource and stores the response.
* The **origin server**, due to delimiter usage, returns user-specific or sensitive data.
* The attacker later accesses the cached version of the crafted path and retrieves the exposed data.

Understanding this discrepancy allows an attacker to craft **cross-behavior payloads** that combine **encoded path traversal** with **delimiter manipulation**, resulting in powerful **Web Cache Deception** exploits even when traditional traversal techniques fail.


### Solution

Before starting, configure FoxyProxy to intercept requests through Burp Suite. Ensure that ‘Intercept’ is turned off in Burp Suite while FoxyProxy is active, so that all requests are logged in the HTTP history. Then, log in to the application using the credentials **wiener:peter**.

Please note that the response will include your API key.

![image](https://github.com/user-attachments/assets/14ebcd29-bd03-4f8b-89a9-329b3703eb18)


In **Proxy > HTTP history**, notice that static resources share the URL path directory prefix `/resources`. Notice that responses to requests with the `/resources` prefix show evidence of caching.

Right-click a request with the prefix `/resources` and select Send to Repeater.

![image](https://github.com/user-attachments/assets/1f338b89-bb86-4a97-bfd5-ba6a8f8d17b7)

In Repeater, add an encoded dot-segment and arbitrary directory before the **/resources** prefix. For example, `/aaa/..%2fresources/YOUR-RESOURCE`.

Send the request. Notice that the 404 response contains the **X-Cache: miss** header.

![image](https://github.com/user-attachments/assets/be50d631-5f81-4c46-9347-e4027064c997)

Resend the request. Notice that the value of the **X-Cache header** updates to **hit**. This may indicate that the cache decodes and resolves the dot-segment and has a cache rule based on the **/resources** prefix. To **confirm** this, you’ll need to conduct further testing. It’s still possible that the response is being cached due to a different cache rule.

![image](https://github.com/user-attachments/assets/bf902fca-8006-4566-b7fc-121d17d86393)



Add an encoded dot-segment after the `/resources` path prefix as follows: `/resources/.%2fYOUR-RESOURCE`.

Send the request. Notice that the **404** response no longer contains evidence of caching. This indicates that the cache decodes and resolves the dot-segment and has a cache rule based on the `/resources` prefix.


![image](https://github.com/user-attachments/assets/66700a78-6da3-44cf-a7cc-44d1bf322ccd)

Go to the **Repeater** tab that contains the **/aaa/..%2fmy-account** request. Use the **?** delimiter to attempt to construct an exploit as follows:
**/my-account%2f%2e%2e%2fresources**

Send the request. Notice that this receives a 200 response with your API key, but doesn’t contain evidence of caching.

![image](https://github.com/user-attachments/assets/11261156-c3cd-48f2-91d6-ed0436d2e647)


Repeat this test using the **%23** and **%3f** characters instead of **?**. Notice that when you use the **%23** character this receives a **200** response with your API key and the `X-Cache: miss` header.

![image](https://github.com/user-attachments/assets/6e3ceef6-36e1-43fe-8448-442bb481ceda)

Resend and notice that this updates to `X-Cache: hit`. You can use this delimiter for an exploit.

![image](https://github.com/user-attachments/assets/e8aeddbc-d4d5-4bf9-91e8-b4ce8db6ad10)


In Burp’s browser, click **Go to exploit server**.

In the **Body** section, craft an exploit that navigates the victim user carlos to a malicious URL. Make sure to add an arbitrary parameter as a cache buster:

```

<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account%23%2f%2e%2e%2fresources?hanzala"</script>

```

![image](https://github.com/user-attachments/assets/57476d36-47d1-4a12-b44f-df946094d326)


Click **Deliver exploit to victim**.

Go to the URL that you delivered to carlos in your exploit:

```
https://YOUR-LAB-ID.web-security-academy.net/my-account%23%2f%2e%2e%2fresources?hanp

```
Notice that the response includes the API key for the user **carlos**. Copy this.

![image](https://github.com/user-attachments/assets/f92082e9-fa7c-40cf-a3e0-bca10d3bb56f)

Click **Submit solution**, then submit the API key for **carlos** to solve the lab.

![image](https://github.com/user-attachments/assets/a78ed3de-8899-4c5a-a25b-d0042200d044)


