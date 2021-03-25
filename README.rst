CORS support library for web servers
====================================

.. image:: https://github.com/zgoda/corslib/workflows/Tests/badge.svg?branch=master
    :target: https://github.com/zgoda/corslib/actions?query=workflow%3ATests
    :alt: Tests

.. image:: https://coveralls.io/repos/github/zgoda/corslib/badge.svg?branch=master
    :target: https://coveralls.io/github/zgoda/corslib?branch=master
    :alt: Test coverage report

.. image:: https://www.codefactor.io/repository/github/zgoda/corslib/badge/master
    :target: https://www.codefactor.io/repository/github/zgoda/corslib/overview/master
    :alt: Code quality report

.. image:: https://readthedocs.org/projects/corslib/badge/?version=latest
    :target: https://corslib.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation status


Policy-based CORS support library for web applications.

This is framework- and protocol-agnostic library that provides CORS policy object that is able to generate both preflight and regular response headers for `Cross Origin Resource Sharing <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>`_.

It tries to be as secure as it's possible while being usable for both development and production. The goal is to provide header generation facility that has no inherent insecurities and does not pruce insecure result under any circumstances.
