## Labs Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy related to **Web Cache Deception**:

**Exploiting path mapping for web cache deception**  
This lab demonstrates how attackers can exploit path mapping weaknesses to trick web caches into storing sensitive pages.

---

### LAB 1 - Exploiting path mapping for web cache deception

### Lab Description

![image](https://github.com/user-attachments/assets/ab7a8cff-9b42-40ff-8e8a-65d5bc9e15c0)

### Overview: Exploiting Static Extensions and Path Mapping Discrepancies

Web cache deception often takes advantage of how caching systems apply rules based on **file extensions** and how **URL paths** are interpreted by different components of a web application.

In many modern web applications:

- The **origin server** may use RESTful routing and ignore extra path segments or file extensions entirely.
- The **cache/CDN** may interpret the same URL **literally**, treating paths ending in `.css`, `.js`, or `.jpg` as static files.

This mismatch creates an opportunity: if sensitive dynamic content (like a user profile or API key) is served at a URL that *appears* static (e.g., `/profile/wcd.css`), the cache may store and serve this sensitive data to **anyone** who requests it.

By testing how both systems interpret URLs, attackers can craft paths that cause private data to be cached under innocuous-looking static resource URLs — effectively leaking it to the public.

This section explores:
- How static extension rules influence caching decisions
- How to detect **path mapping discrepancies**
- How to weaponize these discrepancies to cache dynamic responses using static-like URLs


### Solution

Before starting, configure FoxyProxy to intercept requests through Burp Suite. Ensure that ‘Intercept’ is turned off in Burp Suite while FoxyProxy is active, so that all requests are logged in the HTTP history. Then, log in to the application using the credentials **wiener:peter**.

Please note that the response will include your API key.

![image](https://github.com/user-attachments/assets/d019e1a0-2cb5-48ef-8a33-617dce3721dd)

Go to Burpuite **Proxy > HTTP history**, right-click the GET /my-account request and select **Send to Repeater**.

![image](https://github.com/user-attachments/assets/13067d7c-75db-4944-91af-04b4c5d1eb9d)

Navigate to the Repeater tab. Modify the base path by adding an arbitrary segment; for example, change the path to `/my-account/hanzala`. Send the request and observe that you still receive a response containing your API key. This indicates that the origin server abstracts the URL path to `/my-account`. Additionally, ensure that you receive a **200** response and verify that the request is not cached

![image](https://github.com/user-attachments/assets/5dd0edf8-0848-4689-a0d3-ba78fda37da1)

Add a static extension to the URL path, such as `/my-account/hanzala.js`, and send the request.

Observe the response headers for `X-Cache: miss` and `Cache-Control: max-age=30`. For example:

**X-Cache:** `miss` – This indicates that the response was not served from the cache.

**Cache-Control:** `max-age=30` – This specifies that if the response were cached, it should be stored for 30 seconds.

![image](https://github.com/user-attachments/assets/18fe4e35-f28f-4ede-8343-244b1396c669)


Resend the request within 30 seconds. You should notice that the `X-Cache` header changes to `hit`, indicating that the response was served from the cache. This suggests that the cache interprets the URL path with the `.js` extension and has a caching rule for it.

![image](https://github.com/user-attachments/assets/d45155d7-d2bb-41ea-8b89-6bbc23869512)


So Now we Know that our request is cache lets create the exploit.

In browser, click **Go to exploit server**.

In the **Body** section, craft an exploit that navigates the victim user carlos to the malicious URL that you crafted earlier. Make sure to change the arbitrary path segment you added, so the victim doesn’t receive your previously cached response.

Click **Deliver exploit to victim**. When the victim views the exploit, the response they receive is stored in the cache.

```

<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account/hanzalaa.js"</script>

```

![image](https://github.com/user-attachments/assets/53351c6e-5477-42fd-96f7-2231f255f43b)


Now in Burp Suite, change the path to `/my-account/hanzalaa.js`. Since Carlos's response is stored in the server cache, this request will return the same response. Send the request to retrieve Carlos's API key. Copy it.

![image](https://github.com/user-attachments/assets/95ef3677-a26a-4ba5-8bda-700803c87bfa)

Click Submit solution, then submit the API key for carlos to solve the lab.

![image](https://github.com/user-attachments/assets/a1a15877-7a66-44f0-a58c-664b40b74b8c)



