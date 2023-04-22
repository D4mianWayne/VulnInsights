# .NET Deserialisation


> An example codebase along with it's CodeQL code will be added to the repository soon.

---

### `Newtonsoft.Json` Package

Sure, here's an example of vulnerable .NET code that uses the Newtonsoft.Json package and is vulnerable to JSON deserialization attacks:

```jsx
using System;
using Newtonsoft.Json;

namespace JsonDeserializationExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string json = @"{ ""$type"": ""JsonDeserializationExample.Person, JsonDeserializationExample"", ""Name"": ""John Smith"", ""Age"": 30 }";
            var person = JsonConvert.DeserializeObject<Person>(json);
            Console.WriteLine(person.Name + " is " + person.Age + " years old.");
        }
    }

    class Person
    {
        public string Name { get; set; }
        public int Age { get; set; }
    }
}

```

This code deserializes JSON data into a `Person` object using the `JsonConvert.DeserializeObject` method provided by the Newtonsoft.Json package. The `$type` field in the JSON data is used to specify the type of object to deserialize, allowing an attacker to potentially execute arbitrary code during the deserialization process.

To identify such code patterns, look for the use of the `JsonConvert.DeserializeObject` method (or other similar methods) with user-controlled input data, especially if the `$type` field is being used to specify the object type to deserialize. Additionally, check if any of the types being deserialized are sensitive or could potentially execute malicious code. It's important to always validate user input data before passing it to a deserialization method to prevent JSON deserialization attacks.

[data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2730%27%20height=%2730%27/%3e](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2730%27%20height=%2730%27/%3e)

Can you write one more code where the type is defined but not securely?

Sure, here's an example of a .NET code that uses the `Newtonsoft.Json` package and defines the object type, but is still vulnerable to JSON deserialization attacks due to a lack of input validation:

```jsx
using System;
using Newtonsoft.Json;

namespace JsonDeserializationExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string json = @"{ ""Name"": ""John Smith"", ""Age"": 30 }";
            var objectType = Type.GetType("JsonDeserializationExample.Person, JsonDeserializationExample");
            var person = JsonConvert.DeserializeObject(json, objectType);
            Console.WriteLine(person.GetType().FullName + ": " + ((Person)person).Name + " is " + ((Person)person).Age + " years old.");
        }
    }

    class Person
    {
        public string Name { get; set; }
        public int Age { get; set; }
    }
}

```

In this code, the type of object to deserialize is defined using a string that specifies the fully-qualified name of the object type (`"JsonDeserializationExample.Person, JsonDeserializationExample"`). However, there is no input validation being done on this string, so an attacker could potentially supply a different type name and execute arbitrary code during the deserialization process.

To prevent JSON deserialization attacks, it's important to validate user input data before passing it to any deserialization method, and to avoid using user input to define the type of object to deserialize. Instead, use a fixed set of known types or create a custom `JsonConverter` to handle deserialization of specific types.

[data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2730%27%20height=%2730%27/%3e](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%2730%27%20height=%2730%27/%3e)

Show a secure version of thios

Sure, here's an example of a more secure version of the .NET code using the Newtonsoft.Json package, with input validation and a fixed set of known types:

```jsx
using System;
using Newtonsoft.Json;

namespace JsonDeserializationExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string json = @"{ ""Name"": ""John Smith"", ""Age"": 30 }";
            var person = JsonConvert.DeserializeObject<Person>(json);
            Console.WriteLine(person.GetType().FullName + ": " + person.Name + " is " + person.Age + " years old.");
        }
    }

    class Person
    {
        public string Name { get; set; }
        public int Age { get; set; }
    }
}

```

In this code, the `JsonConvert.DeserializeObject` method is called with the `Person` class as the generic parameter, so the type of object to deserialize is explicitly set and does not rely on user input. Additionally, the input JSON data is not trusted and is validated against the expected schema defined by the `Person` class.

This approach is more secure than the previous example because it avoids using user input to define the type of object to deserialize and validates input data before passing it to the deserialization method.

The `TypeNameHandling` property in Newtonsoft.Json is used to specify how type names should be handled during serialization and deserialization. The `TypeNameHandling` enumeration has four possible values:

- `None` (0): No type name handling is performed.
- `Objects` (1): Only object types are given a type name.
- `Arrays` (2): Only array types are given a type name.
- `All` (3): Both object and array types are given a type name.

References: 

[](https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15)
[](https://medium.com/r3d-buck3t/insecure-deserialization-with-json-net-c70139af011a)