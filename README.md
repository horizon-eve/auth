# Horizon Auth Service
[![doks-staging](https://github.com/horizon-eve/auth/actions/workflows/doks-staging.yml/badge.svg?branch=master)](https://github.com/horizon-eve/auth/actions/workflows/doks-staging.yml)

This service implements eve sso authentication flow as described here: https://docs.esi.evetech.net/docs/sso/

Requires database to store auth data and manage authentication for dependent services

## Features
1. Add / Remove character to user
   1. SSO Step 1: POST /login/link (with valid auth header)
   2. SSO Step 2: GET /login/callback
   3. SSO Step 3: POST /login/verify
