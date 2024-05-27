# Wait, there is more!

* [ ] Have better concept for the public URL
* [ ] Get rid of the public URL altogether – This would require passing through the "connection" information from actix
  to the token generator through `oxide-auth`, which currently seems not possible.
* [ ] Sign tokens
* [x] Public clients
* [ ] Refresh tokens
* [ ] ID tokens
    * [x] Basic token
    * [ ] Align data with access token
    * [ ] Allow injecting more data
* [ ] User info endpoint
    * [x] Basic response
    * [x] Align with ID token data
