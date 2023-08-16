| ![](data/images/fintech_devcon-logo.svg) | ![](data/images/JumpWireLogo_PurpleBlue.svg) |
|:--:|:--:|
|**#fintechdevcon2023**|**Secure software demystified**|

## 🔒 Secure software demistifyed: data security practices

This is the code repository for a workshop given at [fintech_devcon 2023](https://fintechdevcon.io/full-agenda/) titled **"Secure software demistifyed: data security practices"**

During the workshop, a microservice application will be refactored to improve security, organized around the [OWASP Top10](https://owasp.org/Top10/) categories for web application security risks. We will improve authentication and authorization, encryption in transit, encryption at rest, and monitor for security-related events.


| ![](data/images/owasp-top10-mapping.png) |
|:--:|
|*OWASP Top 10*|

The microservice application contains and an API, a background worker, and a database. It runs in Kubernetes using Traefik as the network interface.

The workshop is designed to teach security principles, as opposed to making specific technology choices. Its goal is to help developers improve the security of their applications by implementing zero trust, updating default framework configurations, adding sensitive data protection, and monitoring events for anomalies.

## 👀 Setup

<details>
<summary>Install Docker, k3s and kubectl</summary>


tl;dr
- Install [Docker](https://docs.docker.com/engine/install/)
- Install and configure [k3s](https://docs.k3s.io/installation) or [k3d](https://k3d.io/v5.5.2/) depending on your local operating system
- Install [kubectl](https://kubernetes.io/docs/tasks/tools/)
- **or** if you have an existing Kubernetes cluster running with administrative rights, you can skip this setup

### Overview

This application runs as microservices in Kubernetes. To work through the steps locally, we recommend using [Rancher k3s](https://github.com/k3s-io/k3s), a lightweight Kubernetes installation that is "easy to install, half the memory, all in a binary less than 100 MB."

### macOS

If you are using macOS, use [k3d](https://k3d.io/v5.5.2/) to run k3s. "k3d is a lightweight wrapper to run k3s in docker." So you will need docker installed on your local machine.

After installing k3s, create a cluster to use for this workshop:
```shell
mkdir /tmp/k3dvol
k3d cluster create workshop --port 9080:80@loadbalancer --port 9443:443@loadbalancer --api-port 6443 --image=rancher/k3s:v1.26.6-k3s1 --volume /tmp/k3dvol:/var/lib/rancher/k3s/storage@all --k3s-arg '--disable=traefik@server:*'
```

### Linux (or WSL2)

If you are using Windows with WSL2, you can install k3s without docker. We recommend downloading the [k3s binary directly](https://docs.k3s.io/installation/configuration#configuration-with-binary) instead of using the setup script provided by Rancher. The binary is "useful when performing quick tests that do not merit managing K3s as a system service", which is suitable for this workshop.

```
 wget -q "https://github.com/k3s-io/k3s/releases/download/v1.25.11%2Bk3s1/k3s" -O /tmp/k3s
 sudo mv /tmp/k3s /usr/local/bin/k3s
 sudo chmod u+x bin/k3s
 k3s --version
```

You should see the following output:

```
$ k3s --version
k3s version v1.25.11+k3s1 (582f07cf)
go version go1.19.10
```

To run k3s, use the following command:
```
sudo K3S_KUBECONFIG_MODE="644" k3s server
```

After starting the server for the first time, various configuration files will be added to your OS. For example, to use `kubectl` with the k3s cluster, simply export the Rancher configuration file as an environment variable:

```
$ export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
$ kubectl get pods
```

</details>

## 🖧 Workshop

The microservice application in this workshop starts with a multi-tier architecture that is common to many web applications. It includes an API, background jobs and a database.

![Starting application architecture](./data/images/fintech_devcon-workshop-arch-start.svg)

After making various software and infrastructure changes, the architecture will evolve to include an API gateway, a database gateway, and an observability stack.

![Ending application architecture](./data/images/fintech_devcon-workshop-arch-end.svg)

## Modifying this application

Use your favorite code editor to make modifications to this project. The authors favor emacs and VSCode. While the authors provide change diffs in the exercises below, they encourage you to make the updates without using copy/paste.

As you update code for each exercise, you can push your changes into the k3s cluster using the following commands:

[ADD KUBECTL DEPLOY COMMAND]

## 📝 Exercises
This workshop has the following exercises

1. [A01:2021 Broken Access Control](#a012021-broken-access-control)
1. [A02:2021 Cryptographic Failures](#a022021-cryptographic-failures)
1. [A04:2021 Insecure Design](#a012021-insecure-design)
1. [A05:2021 Security Misconfiguration](#a012021-security-misconfiguration)
1. [A09:2021 Security Logging and Monitoring Failures](#a012021-security-logging-and-monitoring-failures)

### A01:2021 Broken Access Control

The first risk of the OWASP Top 10 is "Broken Access Control".

We will upgrade our API to add both authentication and authorization.

While it is common for external APIs to have basic authentication in place, we will also use authentication for internal requests, such as those coming from our background job. The reason for this is to harden our application against "inside threats", where another internal application has been compromised and attackers are using it to exfiltrate data from our APIs.

This approach is called "zero trust", and the idea is that no requests received by the API should be trusted, even if it is coming from inside our own cloud or network.

In addition to authentication, we will introduce authorization to individual API endpoints. This will give us the ability to generate credentials that only allow a subset of the API functionality to be invoked.

Authorization allows us to use the concept of "least privilege", where users or clients are only allowed to perform the operations that they need. It will also let us map API functions to different personas or roles, such as an administrator vs a normal user.

#### Introducing JSON Web Tokens

JSON Web Tokens, aka JWTs, are most useful for web application auth. They can be validated as authentically generated by our application (as opposed to generated by an attacker), can include information about the client making the request (such as a user id), are fairly tamper-proof, and can be set to expire after some time. Technically speaking, they are semi-structured Javascript Objects (JSON) that gets encoded into a string using base64url.

> Here's a sample encoded JWT - [eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c](https://jwt.io)

A JWT will be passed in an HTTP request header for all requests made to our API, and the API will validate the JWT before processing the request. Easy! (The only downside is that they are long strings, but other than that pretty perfect for auth).

**IMPORTANT NOTE:** Information in a JWT is not secure, and they shouldn't include sensitive information like customer PII. Anyone can easily decode a JWT, just using tools or even the website [https://jwt.io/](https://jwt.io/). JWTs should also be treated like passwords, and not committed into source code or shared publicly.

#### Adding JWT authentication to Express

We'll use a NodeJS library `jsonwebtoken` to generate and validate our JWTs. And we'll load a signing secret, used to generate and validate tokens, from an environment variable using the library `dotenv`.

First let's add that library as a dependency to our API application. Update the [package.json](src/api/package.json) -

```diff
// src/api/package.json
{
  "name": "api",
  "version": "0.0.0",
  "private": true,
  "scripts": {
    "start": "node ./bin/www"
  },
  "dependencies": {
    "config": "^3.3.9",
    "cookie-parser": "~1.4.4",
    "debug": "~2.6.9",
+    "dotenv": "~16.3.0",
    "express": "~4.16.1",
+    "jsonwebtoken": "~9.0.0", 
    "morgan": "~1.9.1",
    "pg": "^8.11.1",
    "sequelize": "^6.32.1"
  }
}
```

Now generate the signing key. This should be kept a secret! It's how the application will know that a token is valid.

Generate some randomness - [https://www.random.org/cgi-bin/randbyte?nbytes=64&format=h](https://www.random.org/cgi-bin/randbyte?nbytes=64&format=h)

Turn it into a single string by copying and pasting the random bytes into this CyberChef recipe - [https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)](https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false))

Now you should have something that looks like this - 
> d318959b6b72c59433baf12fbf9d7c784d1b0b04f0399a63424a04a739283ac663e2a78d4139ae78dd9318999372caf707df14222a018a0333beb8265c92c150

Add it to the API's [Dockerfile](src/api/Dockerfile) as an environment variable by replacing `[your token]` -

```diff
// src/api/Dockerfile
FROM node:18-alpine

ENV NODE_ENV=production
+ENV TOKEN_SECRET=[your token]

RUN apk add --no-cache tini
```

Next up, let's add some code to our API [index.js](src/api/routes/index.js)  to generate tokens for our API. First load the secret from the environment variable -

```diff
// src/api/routes/index.js
const express = require('express');
+const jwt = require('jsonwebtoken');
+require("dotenv").config();
const router = express.Router();
+const token_secret = process.env.TOKEN_SECRET;

router.get('/', function(req, res, next) {
    res.status(404).json({error: "not found"});
});

module.exports = router;
```

And now an endpoint to generate a JWT -

```diff
// src/api/routes/index.js
//...

router.get('/', function(req, res, next) {
    res.status(404).json({error: "not found"});
});

+app.post('/createToken', (_req, res) => {
+  const data = { username: req.body.username }
+  const token = jwt.sign(username, token_secret, { expiresIn: '1800s' });
+
+  res.json(token);
+});

module.exports = router;
```

Next, we'll create a middleware for Express to validate a JWT. Let's add a function that can validate a token. In [src/api](src/api/) create a file called `auth.js` -

```javascript
// src/api/auth.js
const jwt = require('jsonwebtoken');

const headerRegex = /^Bearer (.+)$/i

export function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  // authorization header is of the format "Bearer token"
  const token = authHeader && authHeader.match(headerRegex);

  if (token == null) return res.sendStatus(401)

  jwt.verify(token[1], process.env.TOKEN_SECRET as string, (err, data) => {
    
    if (err) {
      console.log(err);
      return res.sendStatus(401);
    }

    req.user = data;

    next();
  })
}
```

This function will verify that a token is valid: signed by our secret and not expired. It also assigns the token data to a request variable called `user`.

We can use this function for endpoints. Let's update the [user routes](src/api/routes/users.js) -

```diff
// src/api/routes/users.js
const express = require('express');
const { models } = require('../database');
+const { authenticate } = require('../authenticate);
const User = models.user;

const router = express.Router();

/* List all users. */
-router.get('/', async function(req, res, next) {
+router.get('/', authenticate, async function(req, res, next) {
  //...
});

/* Get a single user by ID. */
-router.get('/:id', async function(req, res, next) {
+router.get('/:id', authenticate, async function(req, res, next) {
  //...
});

/* Create a new user. */
-router.post('/', async function(req, res, next) {
+router.post('/', authenticate, async function(req, res, next) {
  //...
});

/* Update an existing user by ID. */
-router.put('/:id', async function(req, res, next) {
+router.put('/:id', authenticate, async function(req, res, next) {
  //...
});

/* Delete an existing user by ID. */
-router.delete('/:id', async function(req, res, next) {
+router.delete('/:id', authenticate, async function(req, res, next) {
  //...
});

module.exports = router;

```

Now each of these routes will require a valid JWT header to be present in the request to process it. Otherwise it will return a 401 response. We can make the same updates to the endpoints in [transactions.js](src/api/routes/transactions.js)

#### Adding authorization

Now that we have basic authentication in place, the next step is to add authorization. This will allow us to issue tokens that can only access some of the endpoints in our API.

First we'll add a list of permissions to the JWT that we generate. Let's update our token -

```diff
// src/api/routes/index.js
//...

router.get('/', function(req, res, next) {
    res.status(404).json({error: "not found"});
});

app.post('/createToken', (_req, res) => {
-  const data = { username: req.body.username }
+  const data = { username: req.body.username, permissions: req.body.permissions }
  const token = jwt.sign(username, token_secret, { expiresIn: '1800s' });

  res.json(token);
});

module.exports = router;
```

Next we'll add an authorization middleware function to `auth.js`. We wrap the middleware function with a parameter, allowing us to specify a permission that must be included in the JWT's user data -

```diff
// src/api/auth.js
const jwt = require('jsonwebtoken');

const headerRegex = /^Bearer (.+)$/i

export function authenticate(req, res, next) {
  //...
}

+export function authorize(permission) {
+  return (req, res, next) => {
+    const user = req.user
+
+    if (user && user.permissions.includes(permission)) {
+      next();
+    }
+
+    return res.sendStatus(401)
+  }
+}
```

Now let's update the endpoints that can create or update users to be accessible only to tokens with a `modify:user` permission in [users.js](src/api/routes/users.js) -

```diff
// src/api/routes/users.js
const express = require('express');
const { models } = require('../database');
-const { authenticate } = require('../authenticate);
+const { authenticate, authorize } = require('../authenticate);
const User = models.user;

const router = express.Router();

/* List all users. */
router.get('/', authenticate, async function(req, res, next) {
  //...
});

/* Get a single user by ID. */
router.get('/:id', authenticate, async function(req, res, next) {
  //...
});

/* Create a new user. */
-router.post('/', authenticate, async function(req, res, next) {
+router.post('/', [authenticate, authorize("modify:user")], async function(req, res, next) {
  //...
});

/* Update an existing user by ID. */
-router.put('/:id', authenticate, async function(req, res, next) {
+router.put('/:id', [authenticate, authorize("modify:user")], async function(req, res, next) {
  //...
});

/* Delete an existing user by ID. */
-router.delete('/:id', authenticate, async function(req, res, next) {
+router.delete('/:id', [authenticate, authorize("modify:user")], async function(req, res, next) {
  //...
});

module.exports = router;
```

Now we're golden!

<details>
<summary>Go deeper</summary>

Historically, "network segmentation", or separating applications by connectivity via a network, has been considered a practical security technique. For example, a company intranet may allow applications to freely connect to other applications on the same intranet.

Like a locked front door of a house, a security team must only ensure that authorized applications or devices connect to this network. That will ensure that malicious actors don't steal data, as they won't be allowed inside.

However this approach has been proven to be ineffective in modern environments, as the number and diversity of applications has grown significantly. Just this year, in 2023, we have seen a hack related to a file transfer utility called MOVEIt [leak data](https://en.wikipedia.org/wiki/2023_MOVEit_data_breach) from thousands of organizations.

While you may think that your backend environment is straightforward or well protected today, this won't be the case as your company or product scales. Retrofitting hundreds of microservices with inter-service authentication would be a huge undertaking down the road.
</details>

### A02:2021 Cryptographic Failures

Add HTTPS!

In addition to encrypting HTTP requests, we need to encrypt requests being made to our database. While it's not on by default, all modern databases support ssl to encrypt their connections.

For PostgreSQL, let's update our [chart](kubernetes/postgres.yaml) to add a certificate used for encryption:
[UPDATE POSTGRES.YAML]

We can configure our application to use ssl mode when connecting, by updating the database configuration in [default.json](src/api/config/default.json)
```diff
// src/api/config/default.json
{
  "database": {
    "dialect": "postgres",
    "host": "localhost",
    "port": 5432,
    "database": "bank",
    "username": "postgres",
-    "password": "postgres"
+    "password": "postgres",
+    "dialectOptions": {
+      "ssl": {
+        "require": true
+      }
+    }
  }
}

```

<details>
<summary>Go deeper</summary>
It used to be standard to "terminate TLS encryption", or decrypt, HTTP requests at a point when they entered the backend. For example, it was common for a load balancer to decrypt an HTTP request before sending it to one of the backend clusters. Or when making inter-service requests between microservices, they would only be configured to use unencrypted HTTP.

Now that attackers are becoming adept at getting access to internal systems, unencrypted requests can be exploited to steal data. This isn't used just for malicious purposes, the NSA famously exploited this to spy on many companies, including [mighty Google](https://en.wikipedia.org/wiki/Tailored_Access_Operations#QUANTUM_attacks)

A common mantra for good security (that is way overused now) is "encrypted in transit and at rest".
</details>

### A04:2021 Insecure Design

Add JumpWire!

#### Introducing API Gateway

An API gateway is an application that sits in front of the API and acts as a single entry point that routes client API requests to your backend microservices. It is useful for adding additional security controls without needing to modify the backend microservices themselves.

We'll use an API gateway to move authentication and authorization out of our Express app. Then we'll add security features, such as `fail2ban`, which can protect against denial-of-service attacks.

K3s comes with a reverse proxy and HTTP ingress controller called Traefik. It has an ecosystem of middleware plugins for extending the capabilities of the proxy to add gateway functionality.

Let's start by adding JWT authentication and authorization to Traefik, so we can move this logic out of Express. We'll use the [traefik-jwt-plugin](https://plugins.traefik.io/plugins/62947304108ecc83915d7782/jwt-access-policy).

First we extend the default k3s traefik configuration to add the plugin. Create the following file at `/var/lib/rancher/k3s/server/manifests/traefik-config.yaml`:

```yaml
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    experimental:
      plugins:
        traefik-jwt-plugin:
          moduleName: "github.com/team-carepay/traefik-jwt-plugin"
          version: "v0.5.1"
```

Then to install the middleware, use the following command:

```shell
$ kubectl apply -f kubernetes/traefik-jwt.yaml
middleware.traefik.containo.us/traefik-jwt-plugin created
```

And restart traefik:

```shell
$ kubectl rollout restart deployment traefik -n kube-system
deployment.apps/traefik restarted
```

[CONFIGURE OPA]

We'll do the same to install [fail2ban](https://plugins.traefik.io/plugins/628c9ebcffc0cd18356a979f/fail2-ban)

Add another plugin entry to `/var/lib/rancher/k3s/server/manifests/traefik-config.yaml`:

```diff
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    experimental:
      plugins:
        traefik-jwt-plugin:
          moduleName: "github.com/team-carepay/traefik-jwt-plugin"
          version: "v0.5.1"
+        fail2ban:
+          moduleName: "github.com/tomMoulard/fail2ban"
+          version: "v0.6.6"
```

And install the middleware:

```shell
$ kubectl apply -f kubernetes/fail2ban.yaml
middleware.traefik.containo.us/fail2ban created
$ kubectl rollout restart deployment traefik -n kube-system
deployment.apps/traefik restarted
```

You can port forward the `traefik` container to view the dashboard:

```shell
$ kubectl get pods -n kube-system
NAME                                      READY   STATUS      RESTARTS       AGE
traefik-56cfc7b59f-4xpqd                  1/1     Running     0              21s
... other pods
$ kubectl port-forward -n kube-system traefik-56cfc7b59f-4xpqd 9000:9000
```

Now open [http://localhost:9000/dashboard/#/](http://localhost:9000/dashboard/#/) in your browser, and you should see the middleware installed successfully:
![](data/images/traefik-dashboard.png)


<details>
<summary>Go deeper</summary>
Architecture design can impact the overall security of an application. By adding components that have a specific purpose, we can ensure that security is applied consistently across many microservices while also reducing the complexity of individual applications.

As we introduce additional API routes, or background jobs, or even new web applications, the gateways can operate agnostic to the technology being used by microservices.

[CWE-501](https://cwe.mitre.org/data/definitions/501.html) lays out the principle of "trust boundaries", which are logical divisions in an application which data moves across. Adding layers that are dedicated to controlling those boundaries give you more control over security.

There is also a strategy called "defense in depth". This describes an approach of not relying on a single control to provide security for a large portion of an application. Instead there should be multiple controls enforcing security, so that when one is compromised, an attacker does not gain "keys to the kingdom". By adding gateways to manage connections between different parts of our archiecture, we decrease the likelihood that a failure can allow for all data to be stolen.
</details>

### A05:2021 Security Misconfiguration

Let's harden our web server by changing the default configuration and adding additional HTTP response headers. Web servers share information about themselves, which can be used to exploit zero-day vulnerabilties that may be discovered.

For example, our API server adds a response header `X-Powered-By: Express`
```shell
$ curl -vv http://localhost:3000
*   Trying 127.0.0.1:3000...
* Connected to localhost (127.0.0.1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.81.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< X-Powered-By: Express
```

This can be easily disabled, add the following configuration to [src/api/app.js](src/api/app.js):

```diff
// src/api/app.js
// ...
const app = express();
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.set('query parser', 'simple');
app.use(cookieParser());
+app.disable('x-powered-by');
```

We can do better. There are lots of headers related to security, such as directing browsers to use HTTPS or restricting other sites from loading your resources. While many of these settings are used by browsers, they are sensible defaults to set on any web server.

Libraries make it easy to configure these settings, and Express has one called `helmet`. Let's update the dependencies in [src/api/package.json](src/api/package.json):

```diff
{
  // ...
  "dependencies": {
    "config": "^3.3.9",
    "cookie-parser": "~1.4.4",
    "debug": "~2.6.9",
    "express": "~4.16.1",
+    "helmet": "~7.0.0",
    "morgan": "~1.9.1",
    "pg": "^8.11.1",
    "sequelize": "^6.32.1"
  }
}
```

And update our app to use the library:
```diff
// src/api/app.js
// ...
const app = express();
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.set('query parser', 'simple');
app.use(cookieParser());
-app.disable('x-powered-by');
+app.use(helmet());
```

If cookies were being used by our web application, we would also want to use a library such as [cookie-session](https://github.com/expressjs/cookie-session) to configure them to use HTTPs and only be readable via HTTP and not javascript.


<details>
<summary>Go deeper</summary>
One overlooked aspect of how attackers operate is "filtering". This is when attackers will narrow a list of targets by ones they believe will be easier to exploit. They try to do this with little effort, with automated scans, looking for known vulnerabilities that have not been patched.

By default, web servers send information about their technology and version. If a server version is known to be vulnerable, it makes for an easy target.

Additionally, absense of security headers in an HTTP response can indicate that a server has not been hardened.
</details>

### A09:2021 Security Logging and Monitoring Failures

Set up logs and alerts!
