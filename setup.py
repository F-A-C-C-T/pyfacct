from setuptools import setup

setup(
    name='pytia',
    version="0.5.20",
    description='Package provides poller for Group-IB Threat Intelligence product',
    python_requires='>=3.6.*',
    install_requires=['requests>=2.25.1', 'dataclasses'],
    packages=['pytia'],
    author='Group-IB',
    author_email='Integration@group-ib.com',
    license='MIT',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown"
)
