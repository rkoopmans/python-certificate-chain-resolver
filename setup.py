import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt', 'r') as fh:
    reqs = fh.readlines()

setuptools.setup(
    name="cert_chain_resolver",
    version="0.2.2",
    author="Remco Koopmans",
    author_email="me@remcokoopmans.com",
    description="Resolve certificate chain by giving a cert as input",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rkoopmans/python-certificate-chain-resolver",
    packages=setuptools.find_packages(),
    install_requires=reqs,
    entry_points={
        'console_scripts': [
            "cert-chain-resolver = cli:cli"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
