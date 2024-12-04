# GraphQL Testing

- Check for introspection, mostly it is not enabled on the production environment but that's where the recon skills comes into consideration. From my personal experience, you can identify it's staging environment (use sublist3r, amass etc.) and then try to send the introspection query, 8/10 times it usually works.
    * Once you have identified the introspection, you can use [GraphQL Voyager](https://graphql-kit.com/graphql-voyager/) to visualize and connect the objects and then try to see what fits the most.
    * If you don't get the introspection to work, it is better to start doing some javascript analysis, most JS files contains the queries/mutations, fields or other potental information that can be used for understanding the schemas better. 
    * [Clairvoyance](https://github.com/nikitastupin/clairvoyance) can also be used as well, this attempts to recover the suggestions and form the schemas on the basis of the returned responses.
- It is important to analyze the field and their respective types whether it is for query or mutations, it may help in retrieving more information that has been intended if any unused field has been found referenced but not returned by the usual constructed query.
- GraphQL APIs are also not safe from the CSRF protections, if the backend server allow the queries to be sent out in urlencoded format, it could be susceptible to CSRF attacks, other factors does come into play when exploitation though such as authentication mechanism.

```graphql
query IntrospectionQuery {
    __schema {
        queryType {
            name
        }
        mutationType {
            name
        }
        subscriptionType {
            name
        }
        types {
            ...FullType
        }
        directives {
            name
            description
            locations
            args {
                ...InputValue
            }
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
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type {
        ...TypeRef
    }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}
```


# Tools

- [InQL](https://github.com/doyensec/inql) - Amazing Burp Plugin, simplifies analysis and exploitation of the GraphQL endpoints.
- [BatchQL](https://github.com/assetnote/batchql)  - Developed by assetnote, this tools performs batched query, basically a single query can perform the same query N number of times.
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance) - Developed by Nikita Stupin, awesome tool to help you out when introspection is disabled.

# Resources

* https://github.com/rtificial-flava/graphQL-mindmap?tab=readme-ov-file - Great mindmap made by rtifical-flava to reference when testing GraphQL endpoints.
* https://www.assetnote.io/resources/research/exploiting-graphql 