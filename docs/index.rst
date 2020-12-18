CORSlib
=======

CORSlib is framework-agnostic library that emits CORS headers on web server side based on defined rules. Policies are applied per request but may be used with arbitrary granularity.

Since it's framework-agnostic, the only thing it can do is to generate preflight response headers related to CORS. It's up to the user to write handler for ``OPTIONS`` request and respond appropriately, including generated headers.

API documentation
-----------------

.. toctree::
    :maxdepth: 2

    modules



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
