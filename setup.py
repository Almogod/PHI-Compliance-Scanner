from setuptools import setup, find_packages

setup(
    name="phi-compliance-scanner",
    version="3.0.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "scan=phi_scanner.cli:main",
        ],
    },
)
