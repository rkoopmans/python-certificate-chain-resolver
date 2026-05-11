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
       print(cert) # Print the certificate object
       print(cert.export())  # Export the certificate in PEM format


Expected output:

.. code-block:: none

   <Cert common_name="cert-chain-resolver.remcokoopmans.com" subject="CN=cert-chain-resolver.remcokoopmans.com" issuer="CN=R3,O=Let's Encrypt,C=US">
   "-----BEGIN CERTIFICATE-----...."
   <Cert common_name="R3" subject="CN=R3,O=Let's Encrypt,C=US" issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
   "-----BEGIN CERTIFICATE-----...."
   <Cert common_name="DST Root CA X3" subject="CN=DST Root CA X3,O=Digital Signature Trust Co." issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
   "-----BEGIN CERTIFICATE-----...."

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


Inspecting cross-signed root variants
-------------------------------------

When the issuing CA's AIA bundle contains more than one certificate sharing the same Subject and public key (a self-signed root plus one or more cross-signed variants by older CAs), those siblings are recorded on the chain as ``cross_signs``. They are kept separate from the main chain so iteration and ``chain.intermediates`` are unaffected.

.. code-block:: python

   from cert_chain_resolver.api import resolve

   with open('cert.pem', 'rb') as f:
       chain = resolve(f.read())

   for cs in chain.cross_signs:
       print("Cross-sign of", cs.subject, "by", cs.issuer)
       print(cs.export())

For a Sectigo R46-issued certificate this might print two cross-signs — one issued by *USERTrust RSA Certification Authority* and one by *AAA Certificate Services* — both with Subject ``Sectigo Public Server Authentication Root R46``.

Detection is purely based on what the CA publishes in its AIA bundle; no external lookups are made. Signatures on cross-sign candidates are not verified by the resolver itself.


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
