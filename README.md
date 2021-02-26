# Jwt Bearer Tests with xUnit

This project was implemented to test the web api project [Jwt Bearer Example][1].

To do that the project [Jwt Bearer Example][1] must be started.

The tests implemented inside the class [RestrictedAccessShoud.cs][2] are:
* Access to public data (`AllowAccessPublicData`, Public Trait)
* Block unauthorized access (`BlockUnauthorizedAccess`, Public Trait)
* Refused invalid login credentials (`RefuseInvalidUserPassword`, Login Trait)
* Successful authentication (`LoginWithSuccess`, Authorized Trait)
* Forbidden access to restricted resources (`ForbiddenAccessAuthenticatedData`, Forbidden Trait)
* Granted access to restricted resources (`AllowedAccessAuthenticatedData`, Authorized Trait)

For a more complete test, some data are inside two classes:
* [InternalRestrictedUrlTestData][3]: test restricted URLs
* [InternalRestrictedAuthorizedAccessData][4]: users credentials and its allowed resources

[1]:https://github.com/jfsant2017/JwtBearerExample
[2]:https://github.com/jfsant2017/JwtBearerExample.Tests/blob/main/RestrictedAccessShould.cs
[3]:https://github.com/jfsant2017/JwtBearerExample.Tests/blob/main/InternalRestrictedUrlTestData.cs
[4]:https://github.com/jfsant2017/JwtBearerExample.Tests/blob/main/InternalRestrictedAuthorizedAccessData.cs
