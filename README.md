# jwt-cpp-mbed
C++ header-only library for creating and validating JSON Web Tokens on ARM Mbed-enabled targets.

## Prior Art
The structure and organization of the library is mostly ported from jwt-cpp:

[https://github.com/Thalhammer/jwt-cpp](https://github.com/Thalhammer/jwt-cpp)

### A Caveat on Exceptions
As we are on Embedded, constrained by resources, and are enforcing the prohibition of exception handling with the GCC compiler flag "-fno-exceptions", all exception handling in the ported-from code has been converted to std::error_code. Naturally, this has altered the program flow somewhat.

## Signature Algorithms
Much as the original jwt-cpp library referenced above, all the following signature algorithms are supported :

* HS256
* HS384
* HS512
* RS256
* RS384
* RS512
* ES256
* ES384
* ES512
* PS256
* PS384
* PS512

## Tested Target :
NUCLEO F767ZI

## Compiler 
GCC ARM 7.3.1

## Build Instructions :
```
mbed test -m nucleo_f767zi -t GCC_ARM --profile my_profile.json --compile -n tests-jwt_tests-unit_tests
```

Then deploy the following image to the target under test and reboot:

```
./BUILD/tests/NUCLEO_F767ZI/GCC_ARM-MY_PROFILE/TESTS/jwt_tests/unit_tests/unit_tests.bin
```

## Output Snippet

```
>>> Running 30 test cases...
{{__testcase_name;Testing base 64 decoding}}
{{__testcase_name;Testing base 64 URL decoding}}
{{__testcase_name;Testing base 64 encoding}}
{{__testcase_name;Testing base 64 URL encoding}}
{{__testcase_name;Testing token format - Missing Dot}}
{{__testcase_name;Testing token format - Invalid Character}}
{{__testcase_name;Testing token format - Invalid JSON}}
{{__testcase_name;Testing decoding of a token}}
{{__testcase_name;Testing creation of a token}}
{{__testcase_name;Testing creation of an HS256 token}}
{{__testcase_name;Testing creation of an RS256 token}}
{{__testcase_name;Testing creation of an RS512 token}}
{{__testcase_name;Testing creation of a PS256 token}}
{{__testcase_name;Testing creation of a PS384 token}}
{{__testcase_name;Testing creation of a PS512 token}}
{{__testcase_name;Testing creation of an ES256 token}}
{{__testcase_name;Testing creation failure of an ES256 token with no private key}}
{{__testcase_name;Testing verification of an RS256 token}}
{{__testcase_name;Testing verification of an RS256 token with only a public key}}
{{__testcase_name;Testing verification failure of an RS256 token with invalid public key}}
{{__testcase_name;Testing verification of an RS512 token}}
{{__testcase_name;Testing verification of an RS512 token with only a public key}}
{{__testcase_name;Testing verification failure of an RS512 token with invalid public key}}
{{__testcase_name;Testing verification of an HS256 token}}
{{__testcase_name;Testing verification failure in the presence of incorrect claim fields}}
{{__testcase_name;Testing verification of an ES256 token}}
{{__testcase_name;Testing verification failure of an ES256 token with invalid public key}}
{{__testcase_name;Testing verification of a PS256 token}}
{{__testcase_name;Testing verification of a PS256 token with only a public key}}
{{__testcase_name;Testing verification failure of a PS256 token with invalid public key}}

>>> Running case #1: 'Testing base 64 decoding'...                                                  
{{__testcase_start;Testing base 64 decoding}}
{{__testcase_finish;Testing base 64 decoding;1;0}}
>>> 'Testing base 64 decoding': 1 passed, 0 failed

>>> Running case #2: 'Testing base 64 URL decoding'...

```

## Output Verification Check
* All test cases should pass execution successfully under the Unity/Utest framework. 
* The board should NOT blink to indicate a fault after the test suite execution.

## Usage Examples
Please consult the test case application for comprehensive examples of how to use each feature of the library. That application is located in :

```
TESTS
└── jwt_tests
    └── unit_tests
        └── TestMain.cpp
```
Just for the sake of brevity, here is a simple illustration of how to decode a token and print the claims :

```c++
#include "mbed.h"
#include "jwt-mbed.h"
#include <cstring>

int main() 
{
    std::error_code expect;
    std::error_code actual;
    std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
    auto decoded = jwt::decode(token, actual);

    if (expect.message() == actual.message())
    {
        for (auto& e : decoded.get_payload_claims())
            printf("%s = %s\r\n", e.first.c_str(), e.second.to_json().to_str().c_str());
    }
}
```
And another to show how to simply sign :
```c++
#include "mbed.h"
#include "jwt-mbed.h"
#include <cstring>

// Define your GOOGLE_PROJECT_ID (const char *) here or some accessible elsewhere.
// Define your GOOGLE_SSL_CLIENT_CERT_PEM (std::string) here or some accessible elsewhere.
// Define your GOOGLE_SSL_CLIENT_PRIVATE_KEY_PEM (std::string) here or some accessible elsewhere.

int main() 
{
    std::error_code expect;
    std::error_code actual;

    std::set<std::string> audience;
    audience.insert(std::string(GOOGLE_PROJECT_ID)); // GOOGLE_PROJECT_ID defined as const char *
    jwt::date now = std::chrono::system_clock::now();
    jwt::date expiry = now + std::chrono::hours(12);
    
    auto token = jwt::create()
        .set_algorithm("RS256")
        .set_type("JWS")
        .set_audience(audience)
        .set_issued_at(now)
        .set_expires_at(expiry)
        .sign(jwt::algorithm::rs256(GOOGLE_SSL_CLIENT_CERT_PEM,
                                    GOOGLE_SSL_CLIENT_PRIVATE_KEY_PEM,
                                    "", ""), actual); // Certificates defined as std::string

    if (expect.message() == actual.message())
    {
        // No errors whilst signing. Go ahead and use token
        printf("Generated JWT token := \n\t%s\n", token.c_str()); 
    }
}
```
The above are mere illustrations. For comprehensive examples that actually compile, consult the aforementioned test application.

## A Note on Dependencies
* The MbedOS version was baselined off of mbed-os-5.11.4 but was modified locally to enable Unity/Utest compile.

* The picojson version was baselined off of the mainstream (i.e. non-Mbed) version, commit 8ba7113451b745b6e4bd83db12f73eefbb315d2e. It was further modified locally in order to suppress all exceptions in a manner that makes sense on the Mbed platform. 
