API
##############

Resolve a certificate chain



   >>> from cert_chain_resolver.api import resolve
   >>> with open('cert.pem', 'rb') as f:
   >>>    fb = f.read()
   >>>    chain = resolve(fb)
   >>>
   >>> for cert in chain:
   >>>   print(cert)
   <Cert common_name="cert-chain-resolver.remcokoopmans.com" subject="CN=cert-chain-resolver.remcokoopmans.com" issuer="CN=R3,O=Let's Encrypt,C=US">
   <Cert common_name="R3" subject="CN=R3,O=Let's Encrypt,C=US" issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">
   <Cert common_name="DST Root CA X3" subject="CN=DST Root CA X3,O=Digital Signature Trust Co." issuer="CN=DST Root CA X3,O=Digital Signature Trust Co.">

