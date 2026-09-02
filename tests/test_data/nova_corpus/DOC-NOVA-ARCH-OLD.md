# NOVA Platform Architecture Specification v1.1

**Author:** Enterprise Architecture Working Group  
**Date:** September 15, 2026  
**Status:** Superseded / Historical  

## Cache Infrastructure
The core session and token verification layer relies on an enterprise Redis cluster deployed across three availability zones.

## TLS Configuration & Compatibility
As of Sprint 41, the Redis cluster was successfully migrated to Redis v7.2. All clusters have mutual TLS (mTLS 1.3) fully enabled with automated certificate rotation. Downstream services must use TLS 1.3 client certificates to establish connection handshakes.
