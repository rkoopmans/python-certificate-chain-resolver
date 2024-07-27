Installation
============

The ``cert_chain_resolver`` tool is available for installation via PyPI or directly from the source. This section provides detailed instructions for both methods to help you get started quickly.

Install via PyPI
----------------

Installing ``cert_chain_resolver`` through PyPI is the simplest and recommended way to get the latest version of the tool. Use the following command to install:

.. code-block:: bash

    $ pip install cert-chain-resolver


Upon installation, the tool will be accessible from your command line as `cert-chain-resolver` within your python environment.

Install from Source
-------------------

1. Clone the Repository:

   .. code-block:: bash

       $ git clone git@github.com:rkoopmans/python-certificate-chain-resolver.git

2. Install the Package:

   .. code-block:: bash

       $ pip install python-certificate-chain-resolver


Run from Source
-------------------

In case you just want to run it, and you already have the dependencies on your system (likely, as they are pretty standard), you can run the cli:

   .. code-block:: bash

       $ python -m cert_chain_resolver.cli certificate.crt > bundle.crt
