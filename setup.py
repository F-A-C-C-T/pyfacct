from setuptools import setup

setup(
    name='cyberintegrations',
    version="0.7.3",
    description='Python library - modules for processing data from the TI and DRP system collected in one library. '
                'This library simplifies work with the products API and gives you the flexibility to customize the '
                'search and retrieval of data from the system.',
    python_requires='>=3.6',
    install_requires=['requests>=2.25.1', 'dataclasses', 'urllib3'],
    packages=['cyberintegrations'],
    author='Сyberintegrations',
    author_email='cyberintegrationsdev@gmail.com',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown"
)
