# Wait, there is more!

* [x] Have better concept for the public URL
* [x] Get rid of the public URL altogether – This would require passing through the "connection" information from actix
  to the token generator through `oxide-auth`, which currently seems not possible.
* [x] Sign tokens
    * [x] HMAC SHA256
    * [ ] Allow other keys/signatures
* [x] Public clients
* [ ] Refresh tokens
* [ ] ID tokens
    * [x] Basic token
    * [ ] Align data with access token
    * [ ] Allow injecting more data
* [ ] User info endpoint
    * [x] Basic response
    * [x] Align with ID token data
