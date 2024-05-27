# Garage Door

> A simple OIDC provider, for demo purposes

## Rationale

OpenID Connect (OIDC) is great, but complicated. There are great solutions out there allowing one to set up an OIDC
provider (server). However, sometimes all of those solutions are pure overkill. All that one would need is a simple
single username/password setup, just a config file, no database, no customizations, no cloud stuff.

That's the itch, this project tries to be the scratch.

## Goals and non-goals

Goals:

* An OIDC provider which can be run stand-alone, serving a list of pre-configured users and clients
* Be useful out of the box
* Follow "the spec"

Stretch goals:

* Allow embedding this into other applications.
* Allow the interoperability with other server frameworks.

Non-goals:

* There's no real "out-of-scope" for this, assuming it makes sense in the OIDC world, and you bring a PR! 😜

## State

This is insecure! But it does allow you to go through some basic authentication flows for public and confidential
clients.

Again, this is insecure! It doesn't even check a password! It doesn't encrypt tokens either. It ignores all kinds of
things that it should not ignore.

However, it allows using it for some cases where a full-blown setup would be required to set up, although it isn't
really required when using it (demo purposes!)

Also see: [ToDo](TODO.md)

## Alternatives

Set up something like Keycloak. It's secure. It's tested. However, I will require a lot more resources. If you want
something secure, that's what is required.

There's an existing project: [`oxide-auth`](https://github.com/HeroicKatora/oxide-auth). I think it's worth checking
out! It actually is the basis for this project.

However, the downside is that it considers itself a toolbox for implementing an OAuth2 providers. Which sounds great,
but also brings quite a lot of complexities due to its goal to be agnostic to all kinds of dependencies. And some of
the important parts (especially for OIDC) are bring-your-own.
