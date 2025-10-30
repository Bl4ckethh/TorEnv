from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="torenv",
    version="1.0.0",
    author="Bl4ckethh",
    author_email="bl4cketh@gmail.com",
    description="Multi-instance Tor proxy with per-request IP rotation for OSINT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/torenv",
    py_modules=["torenv"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "PySocks>=1.7.1",
        "stem>=1.8.2",
    ],
    entry_points={
        "console_scripts": [
            "torenv=torenv:main",
        ],
    },
)
