from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cryptotrace",
    version="1.0.0",
    author="Security Research Team",
    description="CLI-based security testing tool for identifying exposed cryptographic materials",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cryptotrace",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "playwright>=1.40.0",
        "beautifulsoup4>=4.12.0",
        "requests>=2.31.0",
        "jinja2>=3.1.2",
        "pyyaml>=6.0.1",
        "colorama>=0.4.6",
        "click>=8.1.7",
        "python-dateutil>=2.8.2",
    ],
    entry_points={
        "console_scripts": [
            "cryptotrace=cryptotrace.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "cryptotrace": ["templates/*.j2"],
    },
)
