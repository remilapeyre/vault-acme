---
layout: "docs"
page_title: "ACME - Secrets Engines"
sidebar_title: "ACME Sidecar"
sidebar_current: "docs-secrets-acme-sidecar"
description: |-
  The ACME sidecar reponds to the HTTP-01 and TLS-ALPN-01 challenges.
---

# ACME Sidecar

While the Vaul ACME secrets backend can natively solve the DNS-01 challenge when
requesting certificates, a sidecar is needed to solve both the HTTP-01 and the
TLS-ALPN-01 challenges.

## Operation

![ACME Sidecar](/img/acme-sidecar.svg)
