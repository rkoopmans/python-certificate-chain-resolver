CLI Usage Documentation
=======================

The ``cert_chain_resolver`` command-line interface (CLI) allows you to resolve and obtain the certificate chain for a given x509 certificate directly from the command line. This tool outputs the full certificate bundle to `stdout`, allowing you to redirect it to a file or another process.

Getting Started
---------------------

The CLI tool is straightforward to use with either direct file input or piped input from another command.

Examples
---------------------

Using a File
------------

To resolve the certificate chain for a certificate file and save the output to a file:

.. code-block:: bash

   $ cert_chain_resolver certificate.crt > bundle.crt

This command reads the certificate from `certificate.crt`, resolves the full certificate chain, and writes the resulting PEM-encoded certificates to `bundle.crt`.

Using Standard Input (stdin)
-----------------------------

If you prefer to pipe the certificate data into the tool, you can use the following command:

.. code-block:: bash

   $ cat certificate.crt | cert_chain_resolver > bundle.crt

This usage is particularly useful in scripting and pipeline scenarios where the certificate content might be the output from another command rather than a static file.

Options
---------------------

The `cert_chain_resolver` CLI supports several options to customize its behavior:

- ``-i``, ``--info``: Print detailed information about each certificate in the chain.
- ``--include-root``: Include the root certificate in the output if it is available in the chain.
- ``--ca-bundle-path CA_BUNDLE_PATH``: Use your own CA bundle as the root certificate store for completing the chain. By default this tries to pick your system CA bundle.

Each option can be combined to tailor the output to your specific needs.

Examples with Options
---------------------

1. **Output Detailed Information**:

   .. code-block:: bash

      $ cert_chain_resolver -i certificate.crt > bundle.crt

   This command will not only resolve the certificate chain but also print detailed information about each certificate, such as the common name, issuer, and subject details.

2. **Include Root Certificate**:

   .. code-block:: bash

      $ cert_chain_resolver --include-root certificate.crt > bundle_with_root.crt

   If the root certificate is available, it will be included in the output file.

3. **Use System CA Store**:

   .. code-block:: bash

      $ cert_chain_resolver --include-root --ca-bundle-path /path/to/own/bundle.pem certificate.crt > bundle.crt
