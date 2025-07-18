## 🔌 What is a WebSocket?

WebSockets are becoming increasingly popular because they greatly simplify communication between a client and a server.
They enable **bidirectional (full-duplex)** communication over a single, long-lived TCP connection using the **application layer (Layer 7)** of the OSI model.

This allows developers to create **dynamic, real-time web applications** such as instant messaging, online gaming, live dashboards, and photo-sharing apps.

### 🔄 Traditional Communication Limitations

Before WebSockets, web communication followed the **request-response** model:

* **Client initiates / Server responds**:
  Servers could listen for connections, but clients couldn’t maintain persistent listeners. Each action required a new request.

* **Server can’t push without a request**:
  The server could only send data after the client explicitly asked for it.

* **Polling was common**:
  Clients had to continuously poll (refresh) the server to get new data.
  This led to inefficient use of bandwidth and the need for **callback functions** to handle asynchronous responses.

---

## 🌐 HTTP vs WebSockets

| Feature              | HTTP                          | WebSockets                         |
| -------------------- | ----------------------------- | ---------------------------------- |
| **Connection Model** | Request → Response (one-way)  | Bidirectional (full-duplex)        |
| **Persistence**      | Short-lived                   | Long-lived                         |
| **Latency**          | Higher (repeated connections) | Low (persistent connection)        |
| **Use Case**         | Static/standard websites      | Real-time apps (chat, games, etc.) |
| **Initiation**       | Uses HTTP request             | Starts as HTTP, then upgrades      |
| **Data Flow**        | One-way (client → server)     | Two-way (client ⇄ server)          |

WebSockets shine in scenarios that require **low-latency**, **real-time**, or **server-initiated** communication—such as live stock tickers, multiplayer games, or collaborative apps.

---

## 🔧 How is a WebSocket Connection Established?

A WebSocket connection is typically initiated from the **client-side using JavaScript**:

```javascript
var ws = new WebSocket("wss://normal-website.com/chat");
```

* `ws://` is for insecure WebSocket connections.
* `wss://` is for secure (SSL/TLS-encrypted) WebSocket connections.

Once the handshake is complete, the connection remains open and can be used to send and receive messages **in both directions**, until either the client or server closes it.

---
