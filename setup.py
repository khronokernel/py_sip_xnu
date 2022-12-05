from setuptools import setup, find_packages

setup(
    name='py_sip_xnu',
    version='1.0.0',
    author='Mykola Grymalyuk',
    license='BSD 3-Clause License',
    description='Module for querying SIP status on XNU-based systems',
    long_description=open('README.md').read(),
    packages=find_packages(exclude=('tests', 'docs')),
)