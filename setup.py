from setuptools import setup,find_packages
setup(name="phantom",version="2.0.0",author="bad-antics",description="Phantom network operations and stealth scanning framework",packages=find_packages(where="src"),package_dir={"":"src"},python_requires=">=3.8")
