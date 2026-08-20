# burp-zlib-decoder

Burp Suite extension (Jython) that decompresses zlib-encoded HTTP request and
response bodies inline, adding a **Zlib Decoded** tab to the message editor.

Useful for thick clients (e.g. ULCJava-based apps) that use zlib as their
HTTP body encoding.

## Features
- Auto-detects zlib magic bytes (`78 xx`) in request/response body
- Falls back to raw deflate and gzip if standard zlib fails
- Editable — modify decoded payload, Burp re-compresses before forwarding

## Setup
1. Burp → Extender → Options → set Jython standalone JAR
2. Extender → Add → Type: Python → select `ZlibDecoder.py`

## Tested against
- NAVIS N4

Written by AI.
