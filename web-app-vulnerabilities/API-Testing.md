### API Testing

Some tips I have stumbled upon, taken from bug bounty reports, CVEs, CTFs and personal research:

- Read documentation, this is must.
- It is better to check what request method is supported by certain API endpoints.
- Some APIs that handle the parameters may not take the URL delimeter into consideration and may process the special characters as separators/identifiers within the URLs.
- Mass assignment refers to the parameters that can also be sent as part of the request and in certain cases the backend API may take them into consideration and can be used for your own gain. (Think like changing `isAdmin` value from the a request to `/api/user/update` )
- Lastly, perhaps long shot yet to try out the things in every end, it is important to observe the behavior of an application as in how it may be interacting with the internal API and how if taking the 3rd point into account as well, it could result in traversal and exploration of new endpoints.