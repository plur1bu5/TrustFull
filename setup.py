from setuptools import setup, find_packages

setup(
    name='trustkit',
    version='0.1.0',
    description='Active Directory trust attack toolkit',
    author='plur1bu5',
    url='https://github.com/plur1bu5/trustkit',
    packages=find_packages(),
    install_requires=[
        'cryptography>=41.0.0',
        'pyasn1>=0.5.0',
        'pyasn1-modules>=0.3.0',
        'impacket>=0.11.0',
        'six',
    ],
    entry_points={
        'console_scripts': [
            'trustfull=trustkit.cli.main:main',
        ],
    },
    python_requires='>=3.8',
)
