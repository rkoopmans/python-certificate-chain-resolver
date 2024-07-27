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

Using the certifi CA Store for resolving root certs
----------------------------

Not all intermediates provide a resolvable path, but we can create the path by matching it with our own CA bundle 

.. code-block:: python

   from cert_chain_resolver.api import resolve
   from cert_chain_resolver.root.certifi import CertifiStore

   # Load your certificate
   with open('cert.pem', 'rb') as f:
       file_bytes = f.read()

   chain = resolve(file_bytes, root_ca_store=CertifiStore())

   for cert in chain:
       print(cert)


Handling Errors
===============

It's important to handle exceptions when resolving certificate chains, especially in cases where the input certificate is invalid or the chain cannot be fully resolved:

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