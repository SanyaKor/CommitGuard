from setuptools import setup, find_packages

setup(
    name="commitguard",
    version="0.1.0",
    packages=find_packages(),
    python_requires=">=3.12",
    install_requires=["requests",
                      "python-dotenv"],
    entry_points={
        "console_scripts": [
            "commitguard=commitguard.core:main",
        ]
    },
)