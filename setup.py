from setuptools import setup

setup(
    name='cyberintegratioins',
    version="0.7.0",
    description='Package provides pollers',
    python_requires='>=3.6',
    install_requires=['requests>=2.25.1', 'dataclasses', 'urllib3'],
    packages=['cyberintegratioins'],
    author='Group-IB',
    author_email='Integration@group-ib.com',
    license='MIT',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown"
)
