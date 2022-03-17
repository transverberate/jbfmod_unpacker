from setuptools import setup


version = "0.1.0"


setup(
    name="jbfmod_unpacker",
    packages=["jbfmod_unpacker"],
    version=version,
    description="A utility for unpacking/extracting tracker modules packed using Martin Rijks' ToPack utility.",
    author="Counselor Chip",
    install_requires=["twofish"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
)

