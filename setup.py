import setuptools
import os
from cert_chain_resolver import __version__


DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(DIR, "README.md"), "r") as fh:
    long_description = fh.read()

with open(os.path.join(DIR, "requirements.txt"), "r") as fh:
    reqs = fh.readlines()

setuptools.setup(
    name="cert_chain_resolver",
    version=__version__,
    author="Remco Koopmans",
    author_email="me@remcokoopmans.com",
    description="Resolve / obtain the certificate intermediates of a x509 cert",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rkoopmans/python-certificate-chain-resolver",
    packages=setuptools.find_packages(),
    install_requires=reqs,
    entry_points={"console_scripts": ["cert-chain-resolver = cert_chain_resolver.cli:main"]},
    license='MIT',
    license_file='LICENSE.txt',
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
