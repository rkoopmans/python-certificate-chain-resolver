API
##############

The ``cert_chain_resolver`` API helps you resolve and inspect certificate chains (up to the root) from x509 certificates. Below are some practical examples demonstrating how to use the API effectively in various scenarios.

Basic Usage
===========

Resolving a Certificate Chain
-----------------------------

To resolve the full certificate chain for a certificate in PEM format:

.. code-block:: python

   from cert_chain_resolver.api import resolve

   # Load your certificate
   with open('cert.pem', 'rb') as f:
       file_bytes = f.read()

   # Resolve the certificate chain
   chain = resolve(file_bytes)

   # Output certificates
   for cert in chain:
       print(cert)


Expected output:

.. code-block:: none

   <Cert common_name="cert-chain-resolver.remcokoopmans.com" subject="CN=cert-chain-resolver.remcokoopmans.com" issuer="CN=R3,O=Let's Encrypt,C=US">
   <Cert common_name="R3" subject="CN=R3,O=Let's Encrypt,C=US" issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
   <Cert common_name="DST Root CA X3" subject="CN=DST Root CA X3,O=Digital Signature Trust Co." issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">

This will print each certificate in the chain, starting with the leaf and ending with the root, if available.


Advanced Usage
==============

Using the System CA Store or own bundle for resolving root certs
---------------------------------------------------

Not all CA intermediates provide a web traversable path to the root certificate. Therefore we need to find the root ourselves if we want to have the complete chain of trust.

.. code-block:: python

   from cert_chain_resolver.api import resolve, FileSystemStore

   # Load your certificate
   with open('cert.pem', 'rb') as f:
       file_bytes = f.read()

   # Will try to find the root bundle on your systemm will raise if it cannot be found
   chain = resolve(file_bytes, root_ca_store=FileSystemStore())

   # We set our own bundle location
   chain = resolve(file_bytes, root_ca_store=FileSystemStore('/etc/cabundles/mine.pem'))
   
   # We leverage certifi for a trusted root bundle
   import certifi
   chain = resolve(file_bytes, root_ca_store=FileSystemStore(certifi.where()))

   for cert in chain:
       print(cert)


Handling Errors
===============

The following errors may be thrown

.. code-block:: python

   from cert_chain_resolver.api import resolve
   from cert_chain_resolver.exceptions import CertificateChainResolverError, ImproperlyFormattedCert, RootCertificateNotFound

   try:
       with open('invalid_cert.pem', 'rb') as f:
           file_bytes = f.read()
       chain = resolve(file_bytes)
   except RootCertificateNotFound as e:
       print("Unable to find the root certificate")
   except ImproperlyFormattedCert as e:
      print("Unable to parse the certificate")
   except CertificateChainResolverError as e:
      print(f"Base exception, catchall")
