from setuptools import setup

setup(
    name='pytia',
    version='0.5.2',
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
