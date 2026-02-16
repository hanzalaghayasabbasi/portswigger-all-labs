# Large Language Models (LLMs) and Web Attacks

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction


Organizations are rushing to integrate Large Language Models (LLMs) in order to improve their online customer experience. This exposes them to **web LLM attacks** that take advantage of the model's access to data, APIs, or user information that an attacker cannot access directly.  

For example, an attack may:
- Retrieve data that the LLM has access to. Common sources of such data include the LLM's prompt, training set, and APIs provided to the model.
- Trigger harmful actions via APIs. For example, the attacker could use an LLM to perform a SQL injection attack on an API it has access to.
- Trigger attacks on other users and systems that query the LLM.

At a high level, attacking an LLM integration is often similar to exploiting a **server-side request forgery (SSRF)** vulnerability. In both cases, an attacker is abusing a server-side system to launch attacks on a separate component that is not directly accessible.

---

## What is a Large Language Model?

A **large language model**, like me, is an advanced artificial intelligence system designed to understand and generate human-like text based on the input it receives. These models are built using deep learning techniques, particularly using architectures like transformer neural networks.  

They are trained on vast amounts of text data to learn patterns, semantics, and syntax of human language. Large language models are capable of performing various natural language processing tasks such as:
- Text generation
- Summarization
- Translation
- Question answering
- And more.

They are used in a wide range of applications including virtual assistants, chatbots, content generation, language translation, and information retrieval.

**Or:**

Large Language Models (LLMs) are AI algorithms that can process user inputs and create plausible responses by predicting sequences of words. They are trained on huge semi-public data sets, using machine learning to analyze how the component parts of language fit together.  

LLMs usually present a chat interface to accept user input, known as a **prompt**. The input allowed is controlled in part by input validation rules.

### Use cases in modern websites:
- Customer service, such as a virtual assistant.
- Translation.
- SEO improvement.
- Analysis of user-generated content, e.g., to track the tone of on-page comments.

---

## LLM Attacks and Prompt Injection

Many web LLM attacks rely on a technique known as **prompt injection**.  
This is where an attacker uses crafted prompts to manipulate an LLM's output.  
Prompt injection can result in the AI taking actions that fall outside of its intended purpose, such as:
- Making incorrect calls to sensitive APIs
- Returning content that does not correspond to its guidelines

---

## Detecting LLM Vulnerabilities

Our recommended methodology for detecting LLM vulnerabilities is:
1. Identify the LLM's inputs, including both direct (such as a prompt) and indirect (such as training data) inputs.
2. Work out what data and APIs the LLM has access to.
3. Probe this new attack surface for vulnerabilities.

---

## Overview of AI, ML, GenAI, and LLMs

- **Artificial Intelligence (AI)**: A broad term that encompasses all fields of computer science that enable machines to accomplish tasks that would normally require human intelligence. Machine learning and generative AI are two subcategories of AI.
- **Machine Learning (ML)**: A subset of AI that focuses on creating algorithms that can learn from data. ML algorithms are trained on a set of data and then make predictions or decisions about new data.
- **Generative AI (GenAI)**: A type of ML that focuses on creating new data. Often, GenAI relies on the use of large language models to perform the tasks needed to create new data.
- **Large Language Model (LLM)**: A type of AI program that uses ML to perform natural language processing (NLP) tasks. LLMs are trained on large data sets to understand, summarize, generate, and predict new content.

---

## Exploiting LLM APIs, Functions, and Plugins

LLMs are often hosted by dedicated third-party providers.  
A website can give third-party LLMs access to its specific functionality by describing local APIs for the LLM to use.  
For example, a customer support LLM might have access to APIs that manage users, orders, and stock.

---

### How LLM APIs Work

The workflow for integrating an LLM with an API depends on the structure of the API itself.  
When calling external APIs, some LLMs may require the client to call a separate function endpoint (effectively a private API) in order to generate valid requests that can be sent to those APIs.  

#### Example workflow:
1. **Client Prompt**: The user provides input to the LLM.
2. **LLM Response**: The LLM processes the input and might determine that it needs to call a function from an external API.
3. **JSON Object**: The LLM returns a structured set of data (JSON object) containing the necessary information for the client to call the external API.
4. **Client Call**: The client makes a call to the API function using the provided arguments.
5. **Processing Response**: The client receives a response from the API function and processes it.
6. **Appending Message**: The client includes the API function's response in a new message and sends it to the LLM.
7. **LLM Call to API**: The LLM itself calls the external API using the function response.
8. **Summarizing Results**: The LLM summarizes the results of the API call and provides them back to the user.

This workflow can have **security implications**, as the LLM is effectively calling external APIs on behalf of the user but the user may not be aware that these APIs are being called.  
Ideally, users should be presented with a **confirmation step** before the LLM calls the external API.

**Important:** Some LLMs also depend heavily on the dataset provided to them.

<p align="center">
  <img src="https://github.com/user-attachments/assets/5866f812-3fea-476e-a52b-49389f12667e" width="1000" alt="LLM Dataset Influence">
  <br>
  <em>Figure: Illustration showing how an LLM’s output is influenced by its training dataset</em>
</p>


---

## Mapping LLM API Attack Surface

The term **"excessive agency"** refers to a situation in which an LLM has access to APIs that can access sensitive information and can be persuaded to use those APIs unsafely.  
This enables attackers to push the LLM beyond its intended scope and launch attacks via its APIs.

### Steps to map the LLM API attack surface:
- The first stage of using an LLM to attack APIs and plugins is to work out which APIs and plugins the LLM has access to.
- One way to do this is to simply **ask the LLM** which APIs it can access.
- You can then ask for additional details on any APIs of interest.
- If the LLM isn't cooperative, try providing **misleading context** and re-asking the question. For example, you could claim that you are the LLM's developer and so should have a higher level of privilege.

---

