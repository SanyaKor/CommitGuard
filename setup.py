from setuptools import find_packages, setup

setup(
    name="commitguard",
    version="0.1.0",
    packages=find_packages(),
    python_requires=">=3.12",
    package_data={
        "commitguard": ["prompts/*.md"]
    },
    install_requires=[
        "requests",
        "python-dotenv",
        "pydantic>=2,<3",
        "langchain-openai",
        "langchain-core"
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-mock",
            "pytest-asyncio"
        ]
    },
    entry_points={
        "console_scripts": [
            "commitguard=commitguard.core:main"
        ]
    }
)