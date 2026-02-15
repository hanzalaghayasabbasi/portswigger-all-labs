# GraphQL Overview

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)


## Introduction

### What is GraphQL?
GraphQL is an open-source query language for APIs that allows clients to request exactly the data they need from multiple sources. It provides a structured syntax for defining and retrieving data, returning responses that mirror the requested structure. Unlike REST APIs, which may return large response objects or require multiple calls, GraphQL enables precise data retrieval through a single endpoint, reducing over-fetching and under-fetching.

### How GraphQL Works
1. **GraphQL Schema**: Defines the data structure, including types, fields, and relationships.
2. **Operations**:
   - **Queries**: Retrieve data (similar to GET in REST).
   - **Mutations**: Modify data (similar to POST, PUT, PATCH, DELETE in REST).
   - **Subscriptions**: Enable real-time updates via a persistent client-server connection.
3. **Endpoint and HTTP Method**: GraphQL uses a single endpoint, with all operations sent as POST requests. The operation type and name determine how the server processes the request.
4. **Response Format**: Returns JSON objects structured according to the client’s request, unlike REST’s varying response structures.

## GraphQL Schema

### Contract Definition
The GraphQL schema is a contract between the frontend and backend, defining the structure of queryable data. It ensures consistent data exchange.

### Schema Definition Language (SDL)
Schemas are defined using SDL, a human-readable syntax for specifying types, fields, arguments, and more. Example:
```graphql
type Product {
  id: ID!
  name: String!
  description: String
}
```
The `!` denotes non-nullable (mandatory) fields. Schemas must include at least one query and often define mutations.

### Object Types
Most schema types are object types, representing system objects with fields (e.g., scalar, enum, or other object types).

## GraphQL Queries
Queries fetch data from the server, similar to GET requests in REST. Key components:
- **Operation Type**: `query` (optional but recommended).
- **Query Name**: Optional, aids debugging.
- **Data Structure**: Specifies the desired response fields.
- **Arguments**: Optional, for filtering specific data (e.g., by ID).

**Example**:
```graphql
query myGetProductQuery {
  product(id: "123") {
    name
    description
  }
}
```

## GraphQL Mutations
Mutations modify data (add, update, delete), akin to POST, PUT, DELETE in REST. Components:
- **Operation Type**: `mutation`.
- **Mutation Name**: Optional, for debugging.
- **Input**: Specifies data to modify.
- **Returned Data**: Defines the response structure.

**Example**:
```graphql
mutation createProduct {
  createProduct(input: { name: "New Product", listed: true }) {
    id
    name
    listed
  }
}
```

**Response**:
```json
{
  "data": {
    "createProduct": {
      "id": "456",
      "name": "New Product",
      "listed": true
    }
  }
}
```

## Fields
Fields are queryable data items within GraphQL types. Queries and mutations specify which fields to return, and the response mirrors this structure.

**Example**:
```graphql
query {
  employees {
    id
    name {
      firstname
      lastname
    }
  }
}
```

## Arguments
Arguments are values passed to fields, defined in the schema. They enable specific object retrieval.

**Example**:
```graphql
query {
  getEmployee(id: "789") {
    name
    role
  }
}
```
**Note**: Using arguments to access objects directly can lead to vulnerabilities like Insecure Direct Object References (IDOR).

## Variables
Variables allow dynamic arguments, improving query reusability. They are declared, used in the query, and passed via a JSON dictionary.

**Example**:
```graphql
query getEmployee($id: ID!) {
  employee(id: $id) {
    name
    role
  }
}
```
**Variables**:
```json
{
  "id": "789"
}
```

## Aliases
Aliases allow multiple instances of the same field in a query by assigning unique names, bypassing GraphQL’s restriction on duplicate properties.

**Example**:
```graphql
query {
  product1: product(id: "1") {
    name
  }
  product2: product(id: "2") {
    name
  }
}
```
**Note**: Aliases can be used to send multiple queries in one request, potentially bypassing rate limits.

## Fragments
Fragments are reusable query syntax units, reducing redundancy.

**Example**:
```graphql
fragment productInfo on Product {
  id
  name
  description
}
query getProduct {
  product(id: "123") {
    ...productInfo
  }
}
```

## Subscriptions
Subscriptions establish real-time connections (often via WebSockets) for live data updates, useful for applications like chat.

**Example**:
```graphql
subscription {
  messageAdded(channelId: "1") {
    id
    content
  }
}
```

## Introspection
Introspection queries retrieve schema details, aiding development but posing security risks if enabled in production. It can expose sensitive information like field descriptions.

**Example Introspection Probe**:
```graphql
query {
  __schema {
    queryType {
      name
    }
  }
}
```

**Full Introspection Query**:
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
  }
}
fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType { kind name }
}
```

**Note**: Remove `onOperation`, `onFragment`, and `onField` directives if the query fails on some servers.

## Working with GraphQL in Burp Suite
### Viewing and Modifying Requests
Burp Suite’s GraphQL tab displays the query and variables, making it easy to edit and analyze.

<img width="898" height="742" alt="image" src="https://github.com/user-attachments/assets/433d2692-d1c5-4996-a402-c1388140b307" />

### Accessing Schemas via Introspection
1. Identify GraphQL endpoints (e.g., `/graphql`, `/api`).
2. Send the request to Burp’s Repeater.
3. Use `GraphQL > Set introspection query` to insert an introspection query.
4. Send the query to retrieve the schema.
5. For older servers, try `GraphQL > Set legacy introspection query`.
6. Save queries to the site map for further testing.

## GraphQL API Vulnerabilities
GraphQL vulnerabilities often stem from implementation flaws:
- **Introspection Enabled**: Exposes schema details, risking information disclosure.
- **Insecure Direct Object References (IDOR)**: Unsanitized arguments may allow unauthorized data access.
- **CSRF**: Endpoints accepting non-JSON POST or GET requests may be vulnerable.
- **Rate Limit Bypassing**: Aliases can send multiple queries in one request, evading rate limits.
- **Suggestions**: Apollo’s suggestion feature may leak schema details if enabled.

### Finding GraphQL Endpoints
- **Universal Query**: Send `query{__typename}` to check for `{"data": {"__typename": "query"}}` in the response.
- **Common Endpoints**: Test `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`, or append `/v1`.
- **Request Methods**: Try POST, GET, or `x-www-form-urlencoded` to identify accepted methods.

<img width="777" height="602" alt="image" src="https://github.com/user-attachments/assets/12fd4bd6-5ca0-4fd6-a1a3-6f169267d5d5" />

### Exploiting Unsanitized Arguments
Direct object access via arguments can lead to IDOR. Example:
```graphql
query {
  product(id: "3") {
    name
    price
  }
}
```
If `id: "3"` is unlisted, accessing it may reveal sensitive data.

### Bypassing Introspection Defenses
- Insert special characters (e.g., newline) after `__schema`.
- Try alternative methods (e.g., GET or `x-www-form-urlencoded`).

**Example**:
```graphql
query {
  __schema
  { queryType { name } }
}
```

### Visualizing Introspection Results
Use a GraphQL visualizer to map schema relationships. Burp’s InQL extension automates introspection and presents structured results.

### Suggestions
Apollo’s suggestion feature may leak schema details in error messages. Tools like Clairvoyance can recover schemas when introspection is disabled.

## Security Best Practices
- Disable introspection in production.
- Validate content types (accept only `application/json` POST requests).
- Implement CSRF tokens.
- Sanitize arguments to prevent IDOR.
- Monitor and limit query depth/complexity to prevent denial-of-service attacks.

## Tools
- **Burp Suite**: For inspecting and testing GraphQL requests.
- **InQL**: Burp extension for schema exploration.
- **Clairvoyance**: Recovers schemas via suggestions.
- **GraphQL Visualizer**: Visualizes introspection results.

For more details on GraphQL, visit [graphql.org](https://graphql.org). For xAI’s API services, see [x.ai/api](https://x.ai/api).

---
