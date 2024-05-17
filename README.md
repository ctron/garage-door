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

This is a research project to learn about OIDC providers. While the goal is valid, this may never actually work.
Right now it doesn't.

## Alternatives

There's an existing project: [`oxide-auth`](https://github.com/HeroicKatora/oxide-auth). I think it's worth checking
out as it is much more elaborate than this project.

However, the downside is that it considers itself a toolbox for implementing an OIDC provider, which sounds great,
but also brings quite a lot of complexities due to its goal to be agnostic to all kinds of dependencies. And some of
the important parts are bring-your-own.

Actually this project makes use of `oxide-auth`. It's a very opinionated setup of it, adding some OpenID Connect
features.
