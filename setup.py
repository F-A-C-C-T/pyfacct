from setuptools import setup

from pytia.const import TechnicalConsts

setup(
    name='pytia',
    version=TechnicalConsts.library_version,
    description='Package provides poller for Group-IB Threat Intelligence & Attribution product',
    python_requires='>=3.6.*',
    install_requires=['requests>=2.25.1'],
    packages=['pytia'],
    author='Evgeniy Meteliza',
    author_email='e.metelitsa@group-ib.com',
    license='MIT',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown"
)
