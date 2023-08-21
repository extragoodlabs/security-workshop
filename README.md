| ![](data/images/fintech_devcon-logo.svg) | ![](data/images/JumpWireLogo_PurpleBlue.svg) |
|:--:|:--:|
|**#fintechdevcon2023**|**Secure software demystified**|

## 🔒 Secure software demystified: data security practices

This is the code repository for a workshop given at [fintech_devcon 2023](https://fintechdevcon.io/full-agenda/) titled **"Secure software demystified: data security practices"**

During the workshop, a microservice application will be refactored to improve security, organized around the [OWASP Top10](https://owasp.org/Top10/) categories for web application security risks. We will improve authentication and authorization, encryption in transit, encryption at rest, and monitor for security-related events.


| ![](data/images/owasp-top10-mapping.png) |
|:--:|
|*OWASP Top 10*|

The microservice application contains and an API, a background worker, and a database. It runs in Kubernetes using k3d as the microcluster.

The workshop is designed to teach security principles, as opposed to making specific technology choices. Its goal is to help developers improve the security of their applications by implementing zero trust, updating default framework configurations, adding sensitive data protection, and monitoring events for anomalies.

## 👀 Setup

Install Docker, k3d and kubectl

**tl;dr**:
- Install [Docker](https://docs.docker.com/engine/install/)
- Install and configure [k3d](https://k3d.io/v5.5.2/), a lightweight Kubernetes wrapper
- Install [kubectl](https://kubernetes.io/docs/tasks/tools/)
- Install [mkcert](https://github.com/FiloSottile/mkcert)
- Deploy the workshop services
- [Add optional dependencies]

### Overview

This application runs as microservices in Kubernetes. To work through the steps locally, we'll be using [Rancher k3s](https://github.com/k3s-io/k3s), a lightweight Kubernetes installation that is "easy to install, half the memory, all in a binary less than 100 MB." k3s, like most Kubernetes distros, only runs on Linux so we'll also run [k3d](https://k3d.io) which wraps k3s in Docker to make it run anywhere.

First step is to clone this repo!

```shell
$ git clone git@github.com:jumpwire-ai/fintech-devcon-2023.git
$ cd fintech-devcon-2023/
```

Install the dependencies above. After installing k3d, create a cluster to use for this workshop:

```shell
# create a directory to use for kubernetes persistence
$ mkdir /tmp/k3dvol

# create the cluster
$ k3d cluster create workshop \
  --port 9080:80@loadbalancer \
  --port 9443:443@loadbalancer \
  --api-port 6443 \
  --image=rancher/k3s:v1.26.6-k3s1 \
  --volume /tmp/k3dvol:/var/lib/rancher/k3s/storage@all \
  --volume "$(pwd)/kubernetes/traefik-config.yaml":'/var/lib/rancher/k3s/server/manifests/traefik-config.yaml@server:*' \
  --volume "$(pwd)/kubernetes/audit.yaml":'/var/lib/rancher/k3s/server/audit.yaml@server:*' \
  --k3s-arg '--kube-apiserver-arg=audit-policy-file=/var/lib/rancher/k3s/server/audit.yaml@server:*' \
  --k3s-arg '--kube-apiserver-arg=audit-log-path=/var/log/kubernetes/kube-apiserver-audit.log@server:*'

# check the cluster
$ k3d cluster list
NAME       SERVERS   AGENTS   LOADBALANCER
workshop   1/1       0/0      true
```

After creating the cluster, your Kubernetes config (~/.kube/config) will automatically be updated. To use `kubectl` with the cluster:

```shell
$ kubectl config current-context
k3d-workshop

$ kubectl get pods --all-namespaces
NAMESPACE     NAME                                      READY   STATUS      RESTARTS   AGE
kube-system   local-path-provisioner-76d776f6f9-9kswj   1/1     Running     0          20m
kube-system   coredns-59b4f5bbd5-79tkd                  1/1     Running     0          20m
kube-system   svclb-traefik-dfba91fb-8257n              2/2     Running     0          19m
kube-system   helm-install-traefik-crd-rzjr2            0/1     Completed   0          20m
kube-system   helm-install-traefik-sh6bn                0/1     Completed   1          20m
kube-system   traefik-57c84cf78d-4nhf8                  1/1     Running     0          19m
kube-system   metrics-server-68cf49699b-ppfc7           1/1     Running     0          20m
```

Now deploy the services to the cluster:

``` shell
kubectl apply -f kubernetes/postgres.yaml
kubectl rollout status -w statefulset/postgres
kubectl apply -f kubernetes/api.yaml
kubectl rollout status -w deployment/api
kubectl apply -f kubernetes/reconciler.yaml
```

After a minute, the CronJob will trigger and you will see 3 pods (2 running and 1 completed):

``` shell
$ kubectl get pods
NAME                        READY   STATUS      RESTARTS   AGE
postgres-0                  1/1     Running     0          2m7s
api-7858bf6dc9-4szjp        1/1     Running     0          65s
reconciler-28204936-kx2z9   0/1     Completed   0          21s
```

## 🖧 Workshop

The microservice application in this workshop starts with a multi-tier architecture that is common to many web applications. It includes an API, background jobs and a database.

![Starting application architecture](./data/images/fintech_devcon-workshop-arch-start.svg)

After making various software and infrastructure changes, the architecture will evolve to include an API gateway, a database gateway, and an observability stack.

![Ending application architecture](./data/images/fintech_devcon-workshop-arch-end.svg)

## Connecting to the API

A service called `api` is created in Kubernetes that listens on port 80 and forwards it to the API service. You can forward a local connection to this service using kubectl:

``` shell
$ kubectl port-forward svc/api 3000:80
Forwarding from 127.0.0.1:3000 -> 3000
Forwarding from [::1]:3000 -> 3000
```

and then in another shell

``` shell
$ curl -i localhost:3000/users
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 20044
ETag: W/"4e4c-iChHJ1SEQjA0Es1Jbd0WBH9mWLU"
Date: Thu, 17 Aug 2023 18:18:23 GMT
Connection: keep-alive
Keep-Alive: timeout=5

[...json data...]
```

## Modifying this application

Use your favorite code editor to make modifications to this project. While we provide change diffs in the exercises below, we encourage you to make the updates without using copy/paste.

As you update code for each exercise, you can push your changes into the k8s cluster using the `build-deploy` script. To test this, we'll make a small change to the API service and redeploy it.

Make the following code change to the API service:

```diff
// src/api/routes/index.js
const express = require('express');
const router = express.Router();

router.get('/', function(req, res, next) {
-    res.status(404).json({error: "unknown"});
+    res.status(404).json({error: "not found"});
});

module.exports = router;
```

Then run the script to deploy the change:

``` shell
$ ./build-deploy api
sha256:6bbf513f4fd7db092d698e50424a00128a190223ab2b72ba8fc02c3b04ab2346
INFO[0000] Importing image(s) into cluster 'workshop'
INFO[0000] Starting new tools node...
INFO[0000] Starting Node 'k3d-workshop-tools'
INFO[0000] Saving 1 image(s) from runtime...
INFO[0009] Importing images into nodes...
INFO[0009] Importing images from tarball '/k3d/images/k3d-workshop-images-20230817143454.tar' into node 'k3d-workshop-server-0'...
INFO[0011] Removing the tarball(s) from image volume...
INFO[0012] Removing k3d-tools node...
INFO[0012] Successfully imported image(s)
INFO[0012] Successfully imported 1 image(s) into 1 cluster(s)
service/api unchanged
deployment.apps/api unchanged
deployment.apps/api restarted
Waiting for deployment "api" rollout to finish: 1 old replicas are pending termination...
Waiting for deployment "api" rollout to finish: 1 old replicas are pending termination...
deployment "api" successfully rolled out
```

Now in separate terminal tabs, start the port forward:

```shell
kubectl port-forward svc/api 3000:80
```

And issue a request to the API:
```shell
curl -i localhost:3000/
```

You'll see this result:
```text
HTTP/1.1 404 Not Found
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 21
ETag: W/"15-3jlv4LtvSUoQruAmr3ef7Px06u0"
Date: Mon, 21 Aug 2023 15:04:49 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"error":"not found"}
```

## 📝 Exercises
This workshop has the following exercises

1. [A01:2021 Broken Access Control](#a012021-broken-access-control)
1. [A02:2021 Cryptographic Failures](#a022021-cryptographic-failures)
1. [A04:2021 Insecure Design](#a012021-insecure-design)
1. [A05:2021 Security Misconfiguration](#a012021-security-misconfiguration)
1. [A09:2021 Security Logging and Monitoring Failures](#a012021-security-logging-and-monitoring-failures)

### A01:2021 Broken Access Control

The first risk of the OWASP Top 10 is "Broken Access Control".

>Moving up from the fifth position, 94% of applications were tested for some form of broken access control with the average incidence rate of 3.81%, and has the most occurrences in the contributed dataset with over 318k.

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

**IMPORTANT NOTE:** [Server-side revocation list]

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
    "express": "~4.16.1",
+    "jsonwebtoken": "~9.0.0",
    "pg": "^8.11.1",
    "pino": "^8.15.0",
    "pino-http": "^8.4.0",
    "sequelize": "^6.32.1"
  }
}
```

Now generate the signing key. This should be kept a secret! It's how the application will know that a token is valid. We'll create a random string that is stored by Kubernetes and injected as an environment variable for our API backend.

Create some randomness:

```shell
# Create random secret. We'll use the token later to interact with the API
$ kubectl create secret generic api-secrets \
  --from-literal=TOKEN_SECRET=$(cat /dev/urandom | base64 | head -c 64)
secret/jumpwire-secrets created
```

You can read the secret using this command:

```shell
$ kubectl get secret api-secrets -o jsonpath="{.data.TOKEN_SECRET}" | base64 --decode
pVNSnxcBPi4mKBfwvPlMHuNc1xyABEIvNcLC0F9fr2zoSJp9BA5FMbu4dbLpyWpm
```

To load the secret as an environment variable in our API, update the [api.yaml](kubernetes/api.yaml):

```diff
// kubernetes/api.yaml
        env:
        - name: APP_DB_HOST
          value: postgres
        - name: APP_DB_USERNAME
          value: postgres
        - name: APP_DB_PASSWORD
          value: postgres
+        envFrom:
+        - secretRef:
+            name: api-secrets

```

Let's update the API [environment config](src/api/config/custom-environment-variables.json) to read the environment variable:

```diff
// src/api/config/custom-environment-variables.json
{
  "database": {
    "host": "APP_DB_HOST",
    "port": "APP_DB_PORT",
    "database": "APP_DB_DBNAME",
    "username": "APP_DB_USERNAME",
    "password": "APP_DB_PASSWORD"
-  }
+  },
+  "token_secret": "TOKEN_SECRET"
}

```

Next up, let's add some code to our API [index.js](src/api/routes/index.js)  to generate tokens for our API. First load the secret from the environment variable -

```diff
// src/api/routes/index.js
const express = require('express');
+const jwt = require('jsonwebtoken');
const router = express.Router();
+const tokenSecret = require('config').get('token_secret');

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

+router.post('/token', function(req, res) {
+    const claims = { sub: req.body.username }
+    const token = jwt.sign(claims, tokenSecret, { expiresIn: '1800s' });
+
+    res.json({ token} );
+});

module.exports = router;
```

Test it out!

``` shell
./build-deploy api
```

```shell
$ kubectl port-forward svc/api 3000:80
$ curl -X POST http://localhost:3000/token -H 'Content-Type: application/json' -d '{"username":"myfaveusername"}'
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZWJ1c3N5bWFuIiwiaWF0IjoxNjkyNDYyMzUwLCJleHAiOjE2OTI0NjQxNTB9.79AE9f7DVCSGhfi8BC3SMSbbEbRCCf5H-URljMa7xcg"}
```

You can copy the token into [jwt.io](https://jwt.io/) and you should see your username in the payload under the `sub` field.

Next, we'll create a middleware for Express to validate a JWT. Let's add a function that can validate a token. In [src/api](src/api/) create a file called `auth.js` -

```javascript
// src/api/auth.js
const jwt = require('jsonwebtoken');
const tokenSecret = require('config').get('token_secret');

const headerRegex = /^Bearer (.+)$/i;

const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // authorization header is of the format "Bearer token"
    const token = authHeader && authHeader.match(headerRegex);

    if (token == null) return res.sendStatus(401)

    jwt.verify(token[1], tokenSecret, (err, data) => {

      if (err) {
          logger.error(err);
          return res.sendStatus(401);
      }

      req.user = data;

      next();
    })
};

module.exports = {
    authenticate,
};
```

This function will verify that a token is valid: signed by our secret and not expired. It also assigns the token data to a request variable called `user`.

We can use this function for endpoints. Let's update the [user routes](src/api/routes/users.js) -

```diff
// src/api/routes/users.js
const express = require('express');
const { models } = require('../database');
+const { authenticate } = require('../auth');
const User = models.user;

const router = express.Router();

/* List all users. */
-router.get('/', async function(req, res, next) {
+router.get('/', authenticate, async function(req, res, next) {

...

/* Get a single user by ID. */
-router.get('/:id', async function(req, res, next) {
+router.get('/:id', authenticate, async function(req, res, next) {

...

/* Create a new user. */
-router.post('/', async function(req, res, next) {
+router.post('/', authenticate, async function(req, res, next) {

...

/* Update an existing user by ID. */
-router.put('/:id', async function(req, res, next) {
+router.put('/:id', authenticate, async function(req, res, next) {

...

/* Delete an existing user by ID. */
-router.delete('/:id', async function(req, res, next) {
+router.delete('/:id', authenticate, async function(req, res, next) {
```

Now each of these routes will require a valid JWT header to be present in the request to process it. Otherwise it will return a 401 response. We can make the same updates to the endpoints in [transactions.js](src/api/routes/transactions.js).

Finally, we'll secure the token endpoint using our token secret. We don't want just any John to be able to generate a token. Typically this endpoint would be secured with another authentication scheme, like a password login. For this exercise we'll just reuse the token signing secret.

Add one more authentication middleware method to [auth.js](src/api/auth.js):

```diff
// src/api/auth.js

const authenticate = (req, res, next) => {
  //...
}

+const authenticateRoot = (req, res, next) => {
+    const authHeader = req.headers["authorization"];
+    const token = authHeader && authHeader.match(headerRegex);
+
+    if (token == null || token[1] !== tokenSecret) return res.sendStatus(401);
+
+    next();
+};
+
module.exports = {
    authenticate,
+    authenticateRoot,
};
```

And use it on the endpoint generating tokens in [index.js](src/api/routes/index.js):

```diff
// src/api/routes/index.js
const express = require('express');
const jwt = require('jsonwebtoken');
+const { authenticateRoot } = require("../auth");
const router = express.Router();
const tokenSecret = require("config").get("token_secret");

//...

-router.post('/token', function(req, res) {
+router.post('/token', authenticateRoot, function(req, res) {
  //...
});

```

Deploy the API and start port forwarding again:

``` shell
./build-deploy api
kubectl port-forward svc/api 3000:80
```

Now we can generate a token by reading the token secret from the Kubernetes secret `api-secrets`:

```shell
curl -X POST http://localhost:3000/token -H 'Content-Type: application/json' -d '{"username":"debussyman"}' -H "Authorization: Bearer $(kubectl get secret api-secrets -o jsonpath="{.data.TOKEN_SECRET}" | base64 --decode)"
```

#### Adding authorization

Now that we have basic authentication in place, the next step is to add authorization. This will allow us to issue tokens that can only access some of the endpoints in our API.

First we'll add a list of permissions to the JWT that we generate. Let's update our token -

```diff
// src/api/routes/index.js

//...

router.post('/token', (req, res) => {
-    const claims = { sub: req.body.username };
+    const claims = {
+        sub: req.body.username,
+        "https://ftdc.jumpwire.io/permissions": JSON.parse(req.body.permissions)
+    };
    const token = jwt.sign(claims, tokenSecret, { expiresIn: '1800s' });

    res.json({ token });
});

module.exports = router;
```

Next we'll add an authorization middleware function to `auth.js`. We wrap the middleware function with a parameter, allowing us to specify a permission that must be included in the JWT's user data -

```diff
// src/api/auth.js
const jwt = require('jsonwebtoken');
const tokenSecret = require("config").get("token_secret");

const headerRegex = /^Bearer (.+)$/i;

const authenticate = (req, res, next) => {
  //...
};

const authenticateRoot = (req, res, next) => {
  //...
};

+const authorize = (permission) => {
+    return (req, res, next) => {
+      const user = req.user;
+
+      if (user && user["https://ftdc.jumpwire.io/permissions"].includes(permission)) {
+          next();
+      } else {
+          return res.sendStatus(401);
+      }
+    };
+};
+
module.exports = {
    authenticate,
    authenticateRoot,
+    authorize,
};

```

Now let's update the endpoints that can create or update users to be accessible only to tokens with a `modify:user` permission in [users.js](src/api/routes/users.js) -

```diff
// src/api/routes/users.js
const express = require('express');
const { models } = require('../database');
-const { authenticate } = require('../auth');
+const { authenticate, authorize } = require('../auth');
const User = models.user;

//...

/* List all users. */
-router.get("/", authenticate, async (req, res, next) => {
+router.get("/", authenticate, authorize("read:user"), async function(req, res, next) {

//...

/* Get a single user by ID. */
-router.get("/:id", authenticate, async function (req, res, next) {
+router.get("/:id", authenticate, authorize("read:user"), async function(req, res, next) {

/* Create a new user. */
-router.post('/', authenticate, async function(req, res, next) {
+router.post('/', authenticate, authorize("modify:user"), async function(req, res, next) {

//...

/* Update an existing user by ID. */
-router.put('/:id', authenticate, async function(req, res, next) {
+router.put('/:id', authenticate, authorize("modify:user"), async function(req, res, next) {

//...

/* Delete an existing user by ID. */
-router.delete('/:id', authenticate, async function(req, res, next) {
+router.delete('/:id', authenticate, authorize("modify:user"), async function(req, res, next) {
```

Deploy the API and start port forwarding again:

``` shell
./build-deploy api
kubectl port-forward svc/api 3000:80
```

Now we're golden! Let's generate a token with permissions:

```shell
curl -X POST http://localhost:3000/token -H 'Content-Type: application/json' -d '{"username":"debussyman","permissions":"[\"read:user\",\"modify:user\"]"}' -H "Authorization: Bearer $(kubectl get secret api-secrets -o jsonpath="{.data.TOKEN_SECRET}" | base64 --decode)"
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZWJ1c3N5bWFuIiwiaHR0cHM6Ly9mdGRjLmp1bXB3aXJlLmlvL3Blcm1pc3Npb25zIjpbInJlYWQ6dXNlciIsIm1vZGl0eTp1c2VyIl0sImlhdCI6MTY5MjU3NjI2OSwiZXhwIjoxNjkyNTc4MDY5fQ.-hnjCcQh0rFWkALT2kEaVCD2Mm2bk_Lu2eK0P9jjyp4"}
```

Which can be used for requests to our API:

```shell
$ curl -i localhost:3000/users -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZWJ1c3N5bWFuIiwiaHR0cHM6Ly9mdGRjLmp1bXB3aXJlLmlvL3Blcm1pc3Npb25zIjpbInJlYWQ6dXNlciIsIm1vZGl0eTp1c2VyIl0sImlhdCI6MTY5MjU3NjI2OSwiZXhwIjoxNjkyNTc4MDY5fQ.-hnjCcQh0rFWkALT2kEaVCD2Mm2bk_Lu2eK0P9jjyp4"
```

[Add CURL for POST that gets denied]

The last step is to give our background job a token so that it can call our API! (If you run `kubectl get pods`, you might notice that the reconciler pod is crashing).

Let's create another kubernetes secret with a valid JWT for the reconciler app to use:

```shell
APP_TOKEN=$(curl -X POST http://localhost:3000/token -H 'Content-Type: application/json' -d '{"username":"debussyman","permissions":"[\"read:user\",\"modify:user\"]"}' -H "Authorization: Bearer $(kubectl get secret api-secrets -o jsonpath="{.data.TOKEN_SECRET}" | base64 --decode)" | jq -r '.token')
kubectl create secret generic reconciler-secrets \
  --from-literal=APP_TOKEN=$APP_TOKEN
secret/jumpwire-secrets created
```

And load the secret as an environment variable in the chart for the background job [reconciler.yaml](kubernetes/reconciler.yaml):

```diff
// kubernetes/reconciler.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: reconciler
  labels:
    app: reconciler
spec:
  schedule: "*/2 * * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 5
  failedJobsHistoryLimit: 10
  startingDeadlineSeconds: 10
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: reconciler
        spec:
          containers:
          - name: reconciler
            image: ghcr.io/jumpwire-ai/fintech-devcon-reconciler:latest
            imagePullPolicy: IfNotPresent
            env:
            - name: APP_API_URL
              value: http://api
+            envFrom:
+            - secretRef:
+                name: reconciler-secrets
          restartPolicy: OnFailure
```

Let's redeploy the reconciler app, and it should recover from crash looping:

```shell
./build-deploy reconciler
```

<details>
<summary>Go deeper</summary>

Historically, "network segmentation", or separating applications by connectivity via a network, has been considered a practical security technique. For example, a company intranet may allow applications to freely connect to other applications on the same intranet.

Like a locked front door of a house, a security team must only ensure that authorized applications or devices connect to this network. That will ensure that malicious actors don't steal data, as they won't be allowed inside.

However this approach has been proven to be ineffective in modern environments, as the number and diversity of applications has grown significantly. Just this year, in 2023, we have seen a hack related to a file transfer utility called MOVEIt [leak data](https://en.wikipedia.org/wiki/2023_MOVEit_data_breach) from thousands of organizations.

While you may think that your backend environment is straightforward or well protected today, this won't be the case as your company or product scales. Retrofitting hundreds of microservices with inter-service authentication would be a huge undertaking down the road.
</details>

### A02:2021 Cryptographic Failures

Encryption was invented thousands of years ago to protect information from falling into the wrong hands. It's still pretty useful for this today, as information speeds around the Internet near the speed of light.

>Shifting up one position to #2, previously known as Sensitive Data Exposure, which is more of a broad symptom rather than a root cause, the focus is on failures related to cryptography (or lack thereof). Which often lead to exposure of sensitive data.

#### Introducing HTTP connection encryption

For issueing certificates, we'll be setting up [cert-manager](https://cert-manager.io/). This sits in our cluster and issues certificates based on metadata for running services. In a production environment, you would have cert-manager use something like HashiCorp Vault or LetsEncrypt to get valid short-lived certificates, but for this workshop we'll configure it to act as its own certificate authority.

``` shell
# setup cert-manager
$ kubectl apply -f kubernetes/cert-manager.yaml

# check that the pods are ready
$ kubectl get pods --namespace cert-manager

NAME                                      READY   STATUS    RESTARTS   AGE
cert-manager-cainjector-f57bf6b76-d4rqh   1/1     Running   0          2m29s
cert-manager-6c54667669-g2p7r             1/1     Running   0          2m29s
cert-manager-webhook-79cbc7f748-f66tp     1/1     Running   0          2m29s
```

The first thing you'll need to configure after you've installed cert-manager is an Issuer or a ClusterIssuer. These are resources that represent certificate authorities (CAs) able to sign certificates in response to certificate signing requests.

[Install mkcert](https://github.com/FiloSottile/mkcert#installation) if you haven't already. We'll use this to generate a new CA and bootstrap the TLS chain of trust. The CA will be imported into your system trust store and can be removed later with `mkcert -uninstall`.

``` shell
$ mkcert -install
Sudo password:
The local CA is now installed in the system trust store! ⚡️
```

`mkcert -CAROOT` will print out the location of the CA files. These will remain even if you uninstall the CA from your system store. We then import this CA into Kubernetes for cert-manager to use:

``` shell
# inject the CA key and cert as a secret
$ kubectl -n cert-manager create secret generic ca-key-pair \
  --from-file=tls.crt="$(mkcert -CAROOT)/rootCA.pem" \
  --from-file=tls.key="$(mkcert -CAROOT)/rootCA-key.pem"
secret/ca-key-pair created

# also add the CA cert as a ConfigMap for use by any pods
$ kubectl create configmap ca-cert --from-file=ca.crt="$(mkcert -CAROOT)/rootCA.pem"
configmap/ca-cert created

# create a ClusterIssuer to use the secret
$ kubectl apply -f kubernetes/ca-clusterissuer.yaml
clusterissuer.cert-manager.io/ca-issuer created

# verify the ClusterIssuer
$ kubectl get clusterissuer
NAME        READY   AGE
ca-issuer   True    60s
```

And now we can issue certificates for our services:

``` shell
$ kubectl apply -f kubernetes/api-certificate.yaml
certificate.cert-manager.io/api created
```

This will cause cert-manager to issue certificates and store them in Secrets in Kubernetes. Each service will have its own certificate, issued by the same CA. We'll update our services to mount in those certificates and start using them:

```diff
// kubernetes/api.yaml
     app: api
 spec:
   ports:
-   - port: 80
+   - port: 443
      targetPort: http
      name: http
   selector:


...

       labels:
         app: api
     spec:
+      volumes:
+      - name: tls-cert
+        secret:
+          secretName: api-tls
       containers:
       - name: api
         image: ghcr.io/jumpwire-ai/fintech-devcon-api:latest
         imagePullPolicy: IfNotPresent
+        volumeMounts:
+        - name: tls-cert
+          mountPath: /etc/tls
+          readOnly: true
         ports:
         - containerPort: 3000
           name: http
           protocol: TCP
         env:
+        - name: TLS_CERT_DIR
+          value: /etc/tls
         - name: APP_DB_HOST
           value: postgres
```

``` diff
// src/api/bin/www
 var app = require('../app');
 var debug = require('debug')('api:server');
-var http = require('http');
+var https = require('https');
+var fs = require('fs');

...

-var server = http.createServer(app);
+var certDir = process.env.TLS_CERT_DIR || '/etc/tls';
+var server = https.createServer({
+  key: fs.readFileSync(`${certDir}/tls.key`, 'utf8'),
+  cert: fs.readFileSync(`${certDir}/tls.crt`, 'utf8')
+}, app);
```

Deploy the API service with `./build-deploy api`, and start [port-forwarding](#connecting-to-the-api) again when it finishes. Now try an HTTPS request:


``` shell
curl -i https://localhost:3000/
HTTP/1.1 404 Not Found
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 19
ETag: W/"13-ba++C/ABIZmZkDpO1b0jr1uB5S0"
Date: Thu, 17 Aug 2023 20:16:17 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"error":"not found"}
```

It works! And CuRL validated the certificate - this is because we set `localhost` as one of the valid domains in the cert, and the CA bundle is installed locally from mkcert.

![or it's magic](https://media.giphy.com/media/12NUbkX6p4xOO4/giphy.gif)

You may have noticed pods from reconciler are now failing. It is still trying to use HTTP - we need to update it to use HTTPS for its API calls, including validation against the CA.

``` diff
// kubernetes/reconciler.yaml
             imagePullPolicy: IfNotPresent
             env:
             - name: APP_API_URL
-              value: http://api
+              value: https://api
+            - name: TLS_CERT_DIR
+              value: /etc/tls
+            volumeMounts:
+            - name: tls-cert
+              mountPath: /etc/tls
+              readOnly: true
           restartPolicy: OnFailure
+          volumes:
+          - name: tls-cert
+            configMap:
+              name: ca-cert
```

``` diff
// src/reconciler/src/main.rs
 use reqwest::blocking::{Client, ClientBuilder};
 use serde::Deserialize;
 use std::collections::HashMap;
+use std::{env, fs::File, io::Read, path::Path};
 use url::Url;

...

 fn build_client() -> Result<Client> {
-    let client = ClientBuilder::new().build()?;
+    let cert_dir = env::var("TLS_CERT_DIR")?;
+    let cert_path = Path::new(&cert_dir).join("ca.crt");
+    let mut buf = Vec::new();
+    File::open(cert_path)?.read_to_end(&mut buf)?;
+    let cert = reqwest::Certificate::from_pem(&buf)?;
+    let client = ClientBuilder::new()
+        .tls_built_in_root_certs(false)
+        .add_root_certificate(cert)
+        .build()?;
     Ok(client)
 }
```

Once again, build and deploy the service with `./build-deploy reconciler`. The next time that the reconciler cron runs, it will connect to the API using HTTPS and will only trust certificates issued by our CA.

#### Introducing database connection encryption

In addition to encrypting HTTP requests, we need to encrypt requests being made to our database. While it's not on by default, all modern databases support SSL to encrypt their connections.

For PostgreSQL, let's update our [chart](kubernetes/postgres.yaml) to add a certificate used for encryption and tell cert-manager to issue it:

``` diff
// kubernetes/postgres.yaml
       labels:
         app: postgres
     spec:
+      volumes:
+      - name: tls-cert
+        secret:
+          secretName: postgres-tls
       containers:
       - name: postgres
         image: ghcr.io/jumpwire-ai/fintech-devcon-postgres:latest

....

         volumeMounts:
         - name: data
           mountPath: /var/lib/postgresql/data
+        - name: tls-cert
+          mountPath: /etc/tls
+          readOnly: true
         env:
         - name: POSTGRES_USER
           value: postgres
         - name: POSTGRES_PASSWORD
           value: postgres
+        - name: TLS_CERT_DIR
+          value: /etc/tls
   volumeClaimTemplates:
   - metadata:
       name: data
```

<details>
<summary>Note on PostgreSQL in Docker</summary>
The PostgreSQL Docker image is very particular about permissions and ownership of SSL certs. This can be hard to work with in Kubernetes, which will mount in the files from the secret owned by "root". To workaround this our postgres image has a custom entrypoint script that copies the certs out and chowns them before calling the main entrypoint. You can see the nitty gritty details in [data/entrypoint.sh](data/entrypoint.sh).
</details>

``` shell
$ kubectl apply -f kubernetes/postgres-certificate.yaml
certificate.cert-manager.io/postgres created

$ kubectl apply -f kubernetes/postgres.yaml
certificate.cert-manager.io/postgres created
service/postgres unchanged
statefulset.apps/postgres configured
```

If you have psql installed, you can try port forwarding to the PostgreSQL server and verifying that SSL works:

``` shell
# in one shell
$ kubectl port-forward svc/postgres 5432:5432
Forwarding from 127.0.0.1:5432 -> 5432
Forwarding from [::1]:5432 -> 5432

# then in another shell
$ psql "postgresql://postgres:postgres@localhost:5432/bank?sslmode=verify-full&sslrootcert=$(mkcert -CAROOT)/rootCA.pem"
psql (15.3, server 15.3)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

bank=#
```

Now that PostgreSQL is setup with a TLS certificate, we can configure our application to use ssl mode when connecting by updating the database configuration in [default.js](src/api/config/default.js)

```diff
// src/api/config/default.js
+const fs = require('fs');
+
 module.exports = {
     database: {
         dialect: "postgres",
         host: "localhost",
         port: 5432,
         database: "bank",
         username: "postgres",
-        password: "postgres"
+        password: "postgres",
+        dialectOptions: {
+            ssl: {
+                ca: fs.readFileSync(`${process.env.TLS_CERT_DIR}/ca.crt`).toString()
+            }
+        }
     }
 }
```

Build and apply the changes - `./build-deploy api`. Once that's done, the API server will be connecting to PostgreSQL over TLS, and verifying the certificate with our CA.

<details>
<summary>Go deeper</summary>
It used to be standard to "terminate TLS encryption", or decrypt, HTTP requests at a point when they entered the backend. For example, it was common for a load balancer to decrypt an HTTP request before sending it to one of the backend clusters. Or when making inter-service requests between microservices, they would only be configured to use unencrypted HTTP.

Now that attackers are becoming adept at getting access to internal systems, unencrypted requests can be exploited to steal data. This isn't used just for malicious purposes, the NSA famously exploited this to spy on many companies, including [mighty Google](https://en.wikipedia.org/wiki/Tailored_Access_Operations#QUANTUM_attacks)

A common mantra for good security (that is way overused now) is "encrypted in transit and at rest".
</details>

### A04:2021 Insecure Design

As your application's complexity increases, security moves from a concern around individual apps to a concern about the overall architecture.

>A new category for 2021 focuses on risks related to design and architectural flaws, with a call for more use of threat modeling, secure design patterns, and reference architectures. As a community we need to move beyond "shift-left" in the coding space to pre-code activities that are critical for the principles of Secure by Design.

When microservices start to proliferate, it becomes harder to ensure that every backend is implementing security controls correctly. Let's lift these controls into their own layers in our architecture.

#### Introducing API Gateway

An API gateway is an application that sits in front of the API and acts as a single entry point that routes client API requests to your backend microservices. It is useful for adding additional security controls without needing to modify the backend microservices themselves.

We'll use an API gateway to handle ingress (incoming) HTTP requests to our cluster. Then use it to add security features, such as `fail2ban`, which can protect against denial-of-service attacks.

K3s comes with a reverse proxy and HTTP ingress controller called Traefik. It has an ecosystem of middleware plugins for extending the capabilities of the proxy to add gateway functionality.

Let's configure the cluster to use the gateway:
```shell
$ kubectl apply -f kubernetes/api-gateway.yaml
```

Now we don't need to port-forward to make requests to our API microservice! You can simply run a curl command to the cluster:
```shell
$ curl -i localhost:9080/
HTTP/1.1 404 Not Found
Content-Length: 21
Content-Type: application/json; charset=utf-8
Date: Fri, 18 Aug 2023 17:49:19 GMT
Etag: W/"15-3jlv4LtvSUoQruAmr3ef7Px06u0"
X-Powered-By: Express

{"error":"not found"}
```

Now let's install the `fail2ban` middleware, by updating our [kubernetes/apigateway.yaml](kubernetes/api-gateway.yaml):

```diff
+---
+apiVersion: traefik.containo.us/v1alpha1
+kind: Middleware
+metadata:
+  name: fail2ban
+  namespace: kube-system
+spec:
+  plugin:
+    fail2ban:
+      blacklist:
+        ip:
+          - 192.168.0.0/24
+      rules:
+        action: ""
+        actionAbuseipdb: ""
+        backend: ""
+        banaction: ""
+        banactionAllports: ""
+        bantime: 3h
+        chain: ""
+        destemail: ""
+        enabled: "true"
+        fail2banAgent: ""
+        filter: ""
+        findtime: 10m
+        ignorecommand: ""
+        logencoding: UTF-8
+        maxretry: "4"
+        mode: ""
+        mta: ""
+        ports: 0:8000
+        protocol: ""
+        sender: ""
+        urlregexp: ""
+        usedns: ""
+      whitelist:
+        ip:
+          - ::1
+          - 127.0.0.1
+
---
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: strip-api-prefix

...

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: apigateway
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: kube-system-strip-api-prefix@kubernetescrd
+    traefik.ingress.kubernetes.io/router.middlewares: kube-system-fail2ban@kubernetescrd
spec:

...
```

And restart traefik:

```shell
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

#### Introducing JumpWire

Um, what is JumpWire? Similar to an API gateway that secures HTTP requests, [JumpWire](https://github.com/extragoodlabs/jumpwire) proxies and examines SQL queries made to a database. It provides access controls - authenticating clients who attempt to connect to the database. It also enforces authorization, by rejecting queries that attempt to access data that the client is not allowed to read or modify. There are also features for encrypting sensitive data, joining data across separate databases, and enterprise goodies like auditing who is accessing what data.

What sets JumpWire apart from other access tools is its ability to identify different types, or classifications, of data that are commingled in the same database. Some examples of this are customer names and addresses, credit card numbers, passwords or other secrets, email addresses, etc. This enables devs who use JumpWire the ability to create access permissions based on the classification of data being queried, rather than managing permissions for particular tables or columns.

There's not a well defined category for this kind of tool yet, but sometimes it's referred to as a "database firewall". Yet as more applications and analytical tools are connected directly to live databases, there is a growing need for security layers that govern requests and responses being processed by the database. Not unlike an API gateway for backend microservices.

We'll deploy JumpWire to act as a firewall between our API service and database. First we'll generate secrets for the engine:

``` shell
# Create random secrets. We'll use the token later to interact with the API so we'll store it in on disk.
$ mkdir -p ~/.config/jwctl
$ cat /dev/urandom | base64 | head -c 64 > ~/.config/jwctl/.token
$ kubectl create secret generic jumpwire-secrets \
  --from-literal=JUMPWIRE_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  --from-literal=JUMPWIRE_ROOT_TOKEN=$(cat ~/.config/jwctl/.token)
secret/jumpwire-secrets created
```

Then we can deploy the image to our Kubernetes cluster. This is already configured to generate a TLS certificate from cert-manager and inject it into the pod, just like we did with our other services.

``` shell
$ kubectl apply -f kubernetes/jumpwire.yaml
certificate.cert-manager.io/jumpwire created
service/jumpwire created
configmap/jumpwire-config created
deployment.apps/jumpwire created

# wait for the deployment to be ready
$ kubectl rollout status -w deployment/jumpwire
Waiting for deployment "jumpwire" rollout to finish: 0 of 1 updated replicas are available...
deployment "jumpwire" successfully rolled out
```

Take a look at the [configuration](kubernetes/jumpwire.yaml) for JumpWire. It specifies a couple of interesting things to do with our data. We assign labels to some fields in the `users` tables:

``` yaml
credit_card: pci
email: pii
password_hash: secret
```

Then we define rules around those labels. The rules say that `pci` - which corresponds to the `credit_card` field - will be encrypted, and `secrets` - the `password_hash` field - will get dropped from results. There are exceptions for the rules that we can use later, but right now they will always apply.

We have a client defined as well, with an id of `ccf334b5-2d5a-45ee-a6dd-c34caf99e4d4`. Clients in JumpWire can be either dynamically authenticated or issued static credentials. For a service account like our API, we'll issue static credentials.

``` shell
# start port forwarding for the JumpWire API
$ kubectl port-forward svc/jumpwire 4443:443
Forwarding from 127.0.0.1:4443 -> 4443
Forwarding from [::1]:4443 -> 4443

# Use the jwctl to generate credentials. This will use the token we previously
# saved to ~/.config/jwctl/.token
$ jwctl -u https://localhost:4443 client token
[INFO] Token generated:

username: 0779b97a-c04a-48f9-9483-22e8b0487de4
password: SFMyNTY.g2gDaAJtAAAAC29yZ19nZW5lcmljbQAAACRjY2YzMzRiNS0yZDVhLTQ1ZWUtYTZkZC1jMzRjYWY5OWU0ZDRuBgBM10gLigFiEswDAA.Zk31CwFi-ClR2ggAY6KJ7rMNvp5aHK7PXndrE8mCaU8

# Save the login info to a new Kubernetes secret - make sure to use the password from your
# deployment, copying the one below will not work!
$ kubectl create secret generic api-postgres-login \
  --from-literal=APP_DB_USERNAME=0779b97a-c04a-48f9-9483-22e8b0487de4 \
  --from-literal=APP_DB_PASSWORD=SFMyNTY.g2gDaAJtAAAAC29yZ19nZW5lcmljbQAAACRjY2YzMzRiNS0yZDVhLTQ1ZWUtYTZkZC1jMzRjYWY5OWU0ZDRuBgBM10gLigFiEswDAA.Zk31CwFi-ClR2ggAY6KJ7rMNvp5aHK7PXndrE8mCaU8
secret/api-postgres-login created
```

Now that the credentials are in a Secret, we'll update our API deployment to use them and connect through JumpWire to the database.

``` diff
// kubernetes/api.yaml
         env:
         - name: TLS_CERT_DIR
           value: /etc/tls
         - name: APP_DB_HOST
-          value: postgres
+          value: jumpwire
-        - name: APP_DB_USERNAME
-          value: postgres
-        - name: APP_DB_PASSWORD
-          value: postgres
+        envFrom:
+        - secretRef:
+            name: api-postgres-login
```

Run `./build-deploy api` to deploy the update. Now when you query the API service, the results will look different. The credit_card field will be encrypted and the password_hash field will have a null value for every user.

``` shell
$ curl https://localhost:3000/users | jq '.[:2]'
[
  {
    "id": 0,
    "credit_card": "jumpwire_AQNwY2kBK0FFUy5HQ00uVjEuNzM0QzEzRTIwN0Y0NkU5NzE2N0U2ODFEQUM1MzA0QTHcmliKjSZ0EYz0MNgt9aGaVcNrsUDdBzRa/fs7SBQYEdDa2CIXEBSqg+k6",
    "currency": "USD",
    "email": "selena_autem@hotmail.com",
    "is_active": true,
    "country": "NO",
    "num_logins": 71,
    "password_hash": null,
    "username": "arnulfo_consectetur",
    "created_at": "2002-11-23T22:22:10.441Z"
  },
  {
    "id": 1,
    "credit_card": "jumpwire_AQNwY2kBK0FFUy5HQ00uVjEuNzM0QzEzRTIwN0Y0NkU5NzE2N0U2ODFEQUM1MzA0QTEHosM0BkbnHKssxskm+ssCRzNesWAplC7chfSF6GnU8FLI1Jc+AulmR9w7",
    "currency": "USD",
    "email": "earnestine_ipsam@hotmail.com",
    "is_active": true,
    "country": "AR",
    "num_logins": 33,
    "password_hash": null,
    "username": "carson_et",
    "created_at": "2010-06-02T22:10:45.724Z"
  }
]
```

<details>
<summary>Go deeper</summary>
Architecture design can impact the overall security of an application. By adding components that have a specific purpose, we can ensure that security is applied consistently across many microservices while also reducing the complexity of individual applications.

As we introduce additional API routes, or background jobs, or even new web applications, the gateways can operate agnostic to the technology being used by microservices.

[CWE-501](https://cwe.mitre.org/data/definitions/501.html) lays out the principle of "trust boundaries", which are logical divisions in an application which data moves across. Adding layers that are dedicated to controlling those boundaries give you more control over security.

There is also a strategy called "defense in depth". This describes an approach of not relying on a single control to provide security for a large portion of an application. Instead there should be multiple controls enforcing security, so that when one is compromised, an attacker does not gain "keys to the kingdom". By adding gateways to manage connections between different parts of our archiecture, we decrease the likelihood that a failure can allow for all data to be stolen.
</details>

### A05:2021 Security Misconfiguration

>Moving up from #6 in the previous edition, 90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4%, and over 208k occurrences of a Common Weakness Enumeration (CWE) in this risk category. With more shifts into highly configurable software, it's not surprising to see this category move up.

208,000 web servers with vulnerabilities is a lot! However that's not surprising, many vulnerabilities are discovered years after a particular version of software has been released. Unless you are paying very close attention, it's not impossible that one of your microservices has a weakness.

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
    "pg": "^8.11.1",
    "pino": "^8.15.0",
    "pino-http": "^8.4.0",
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

One thing that trips up devs is the `Content-Security-Policy` header. Trying to read one is tricky, it's a long list of keywords and urls. But this is a powerful header, as you can very granularly define where content on the page can be loaded from, which offers protection against all kinds of malicious attacks that try to hijack your visitors.

Just keep in mind the header follows the following format:
```
[content type] 'self' [list of valid hosts for content type]; [repeat]
```

This is a [handy resource](https://content-security-policy.com/) listing content types and examples.


<details>
<summary>Go deeper</summary>
One overlooked aspect of how attackers operate is "filtering". This is when attackers will narrow a list of targets by ones they believe will be easier to exploit. They try to do this with little effort, with automated scans, looking for known vulnerabilities that have not been patched.

By default, web servers send information about their technology and version. If a server version is known to be vulnerable, it makes for an easy target.

Additionally, absence of security headers in an HTTP response can indicate that a server has not been hardened.
</details>

### A09:2021 Security Logging and Monitoring Failures

>Security logging and monitoring came from the Top 10 community survey (#3), up slightly from the tenth position in the OWASP Top 10 2017. Logging and monitoring can be challenging to test, often involving interviews or asking if attacks were detected during a penetration test.

Set up logs and alerts!

Logging, and observability in general, is a deep topic with many approaches, tools, and vendors. In a security context, one aspect that's critical is aggregating access events into a single location. Even just starting with manual reviews gives a decent foundation that can be built on over time.

We'll use the EFK stack to aggregate our logs:

- Elasticsearch stores, indexes, and searches logs
- Fluentd watches for new logs and events and sends them to Elasticsearch
- Kibana visualizes our searches and can perform alerting

In our setup, fluentd will run on every Kubernetes node and tail the logs of every pod. It will attach metadata to the log context (IP address, pod name, etc) before forewarding them. This mostly works out of the box - the full setup is in [kubernetes/efk-manifests.yaml](kubernetes/efk-manifests.yaml).

``` shell
# everything will be created under a new namespace, `logging`
$ kubectl apply -f kubernetes/efk-manifests.yaml
namespace/logging created
service/elasticsearch created
statefulset.apps/elasticsearch created
service/kibana created
configmap/kibana created
deployment.apps/kibana created
serviceaccount/fluentd created
clusterrole.rbac.authorization.k8s.io/fluentd created
clusterrolebinding.rbac.authorization.k8s.io/fluentd created
daemonset.apps/fluentd created

$ kubectl -n logging port-forward service/kibana 5601:5601
Forwarding from 127.0.0.1:5601 -> 5601
Forwarding from [::1]:5601 -> 5601
```

Kibana is now accessible at [http://localhost:5601](http://localhost:5601). When you connect in your browser, Kibana will prompt you to "Create data view".

![](images/kibana-init.png)

Click that button and enter a pattern to view our indexes in Elasticsearch. Set the Name to `logs` and the `Index pattern` to `logstash-*`. This will match the daily rotated logs indexes coming in from fluentd.

![](images/kibana-index.png)

Click `Save data view to Kibana` and you'll be redirected to the logs view you created. All of our logs for Kubernetes is available and can be filtered by labels. Let's take a look at an API log event - set the search bar to `kubernetes.labels.app : api and res.statusCode : 200`. Click the toggle on the left side of an event to view all the details about it (there may be more than one page in the details panel).

![](images/kibana-details.png)

Whoops! Our logs include all of the HTTP request headers - including the JWT! There are two approaches we can take to solve this. Either make the logs very minimal and explicitly set context we care about, or block specific pieces of context from being included. There are pros and cons for each; for HTTP headers we (usually) know what keys are sensitive, so taking the latter approach makes sense.

Many logging frameworks support some form of redaction or filtering, and the library we're using [does as well](https://getpino.io/#/docs/redaction). We'll update the config to redact any authorization request headers:

``` diff
// src/api/app.js
const app = express();
-app.use(loggerMiddleware({ logger }));
+app.use(loggerMiddleware({
+    logger,
+    redact: ['req.headers.authorization'],
+}));
```

Deploy that and make a new request, or wait for the CronJob to fire. Kibana will now have the value `[REDACTED]` instead of the bearer token.

![](images/kibana-redacted.png)

The logs can be really useful but they are a bit noisy right now. Let's narrow it down to just security related events. Clear the search bar first for a clean start, then, hit the plus icon in the top left to add a filter. Choose `module` for the field name with an operator of `is` and a value of `auth`. Click "Add filter" - now the dashboard only shows events coming from our auth.js module! It's still a bit noisy, so let's choose which fields to show. For each field in the left, you can click the plus button to add it as an event column. Do this for `msg`, `kubernetes.labels.app`, `kubernetes.pod_name`, and `user` - now our dashboard is ready to go.

![](images/kibana-filtered.png)

<details>
<summary>Go deeper</summary>
There are a lot more interesting events you can define to turn this basic dashboard into a security machine. A good starting place is the Kubernetes [audit log](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/). This is ingested by fluentd already and gives you insight into what users or services are doing on the Kubernetes control plane.

Kibana can also define rules for generating alerts. This is a great way to bootstrap a basic SIEM - it won't have all of the power of a dedicated SIEM, but it's a fairly simple way to get something usable quickly.

For more info, check out [Kibana's documentation](https://www.elastic.co/guide/en/kibana/current/alerting-getting-started.html).
</details>
