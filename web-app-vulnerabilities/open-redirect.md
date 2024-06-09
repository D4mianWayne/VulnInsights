### Overview

Open redirect is a vulnerability where you control a specific parameter of a URL which in turns makes the target application redirects the user (or you) to the specified website. This is rather used for phishing attacks and has more or less the impact of medium/low depending on how the redirection affects. 

Open Redirect generally happens when you see a GET request such as following:

```java
https://domain.com/hello.php?url=/user/profile
```

In this case, if you end up identifying that  the `url` parameter redirects you to [`google.com`](http://google.com) when while fuzzing your way through with

```java
https://domain.com/hello.php?url=https://google.com
```

In more modern application, there are several restrictions which will prevent open redirect often by checking the input of parameter in concern through some regular expression matching or whitelisting while checking for paths within said web application.

---

### Testing for Open Redirect

Testing for open redirect is rather straightforward as in most cases you’re looking for a GET request which is being made by the application and has a parameter which is controlling the flow of the requests, like the example we had in the former section, in that case we saw the application is keeping track of page using the `url` parameter which means that the application is handling the flow using that parameter in some manner. So, at the end of the way, it will take a bit of manual work to go through all kind of request the application is making and identify similar pattern as we discussed.

Often times, it is important as well to look for the DOM elements within the JavaScript where your controlled input may end such as during processing of the parameters from the GET requests, the parameter is placed in the value of `window.location.href` where the location of the current window (DOM element for the current page) is being set with the controlled input.

But since we now live in 2024, there are many applications which are secure of traditional open redirect vulnerabilities by making use of secure regex to match their subdomain, in case of OAuth, imagine that for the `redirect_uri` it explicitly check if the parameter contains one of their subdomains such as `<subdomain>.<domain>.tld` , here it is better to fuzz your way to see if there could be any loophole to make use of. Something that I have found useful is the following RECollapse tool which was introduced by [0xacb]

https://github.com/0xacb/recollapse

This is an amazing tool which generates a list of payloads containing special characters that can be sent by something like Burp Intruder or `ffuf` targeting the fields to bypass any underlying regex which is blocking our way.

This was useful to myself as I found an open redirect on a big site as part of pentest assessment, in my case `?` character was not being sanitized and giving something like:

```java
https://domain.com/logout?url=https://google.com?domain.com
```

Doing so I got successful redirect to [`google.com`](http://google.com) 

<aside>
💡 There is an interesting read on one of the way to bypass interstitial pages, that too found on hackerone:  https://www.hackerone.com/reports/101962/

</aside>

---

### References:

- https://www.hackerone.com/reports/101962/ - HackerOne Interstitial Redirect
- https://www.hackerone.com/reports/103772/ - Shopify Login Open Redirect
- https://hackerone.com/reports/119236 - Uber Open Redirect

# Reporting Template

With regards to the notes above, following is the generic template for the Open Redirect one may wanna use for their pentest report:

**Description:** 

Open redirect vulnerabilities occur when attackers manipulate certain parameters in a URL to trick a web application into redirecting users to a different, often malicious, website. This manipulation can occur through user-supplied input or by exploiting flaws in the application's logic.

The impact of open redirect vulnerabilities can be significant. Attackers can exploit them to craft convincing phishing attacks, where users are directed to fake login pages or other deceptive websites designed to steal their credentials or sensitive information. Moreover, open redirects can be used as part of larger attack chains, where they serve as a stepping stone for further exploitation. For example, an attacker might use an open redirect to disguise the malicious URL of a drive-by download or to redirect users to a website hosting malware.

**Solution:**

To mitigate open redirect vulnerabilities, developers should implement several key strategies:

1. **Input Validation:** Validate and sanitize all user-supplied input, including URL parameters, to ensure they conform to expected formats and do not contain malicious payloads. This can involve using server-side validation techniques such as input validation libraries or regular expressions.
2. **Whitelisting:** Implement whitelisting mechanisms to restrict the destinations to which the application can redirect users. Whitelists should include only trusted URLs or URL patterns, preventing attackers from redirecting users to arbitrary or malicious websites.