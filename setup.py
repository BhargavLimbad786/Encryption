from setuptools import setup, find_packages

# Read the contents of the README file
with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="encryptions",  # Name of your package
    version="1.0.0",      # Initial version number
    author="Bhargav Limbad",  # Your name
    author_email="bhargav@e6x.io",  # Your email
    description="A simple AES and RSA encryption package",  # Short description
    long_description=long_description,  # Detailed description (from README)
    long_description_content_type="text/markdown",  # Markdown format
    url="https://github.com/BhargavLimbad786/Encryption",  # URL to your project repository
    packages=find_packages(),
    install_requires=["pycryptodome"],   # Automatically find packages in the current directory
    classifiers=[  # A list of classifiers that help users find your package
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',  # Minimum Python version
    # test_suite='tests',  # Automatically find test files in the tests folder
)
