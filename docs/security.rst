Security measures
=================

"null" origin
-------------

"null" origin can be matched only with ``STR`` rule kind, this means it must be specifically added to list of policy's rules. It will fail to match against both ``PATH`` and ``REGEX`` rules, no matter what. This is to make it clear that this special origin is treated accordingly. The policy enforces some basic restrictions:

* credentialed requests are explicitly disallowed
* only simple request methods are allowed (``GET``, ``HEAD``, ``POST``)
* only `safe headers <https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_request_header>`_ are allowed

In this specific case all policy settings are overriden by safe settings.

.. note::
    W3C `advises against <https://w3c.github.io/webappsec-cors-for-developers/#avoid-returning-access-control-allow-origin-null>`_ returning ``null`` as allowed origin but there are valid use cases when some level of access can be granted. In case this advice should be observed, both preflight and response generation methods accept ``strict`` argument, which turns on *strict mode* that disables CORS headers generation in case of ``null`` request origin.
