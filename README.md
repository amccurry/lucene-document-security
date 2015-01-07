lucene-document-security
========================

Provides an API for Document level security in Lucene.


Current Performance Specs using the LoadTest program with 100 Million Documents:

This test was run a small instance in Digital Ocean.  So it will likely be faster on bare metal hardware.

The user based query was a MatchAllDocuments query so the access control overhead is at it's worst because it has to check every document in the index.

DocValue Impl - Index Creation Time [896326.640162 ms]
======

Pass 1
======
* No Security   : 100000000 326.194433 ms
* No Access     : 0         27426.168612 ms
* Access to All : 100000000 15762.119332 ms

Pass 2:
======
* No Security   : 100000000 298.460303 ms
* No Access     : 0         26305.219079 ms
* Access to All : 100000000 15475.377744 ms



Filter Impl - Index Creation Time [998150.523051 ms]
======

Pass 1:
======
* No Security   : 100000000 377.144582 ms
* No Access     : 0         985.46436 ms
* Access to All : 100000000 1215.554028 ms

Pass 2:
======
* No Security   : 100000000 252.667496 ms
* No Access     : 0         866.96378 ms
* Access to All : 100000000 910.320593 ms
