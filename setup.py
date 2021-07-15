from setuptools import setup

setup(
    name='pytia',
    version='0.4.0',
    description='Package provides poller for Group-IB Threat Intelligence & Attribution product',
    python_requires='>=3.6.*',
    install_requires=['requests>=2.25.1'],
    packages=['pytia']
)
