from setuptools import setup

setup(
    name='cyberintegrations',
    version="0.7.1",
    description='Package provides pollers',
    python_requires='>=3.6',
    install_requires=['requests>=2.25.1', 'dataclasses', 'urllib3'],
    packages=['cyberintegrations'],
    author='Сyberintegrations',
    author_email='cyberintegrationsdev@gmail.com',
    license='MIT',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown"
)
