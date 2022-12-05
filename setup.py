from setuptools import setup, find_packages

setup(
    name='py_sip_xnu',
    version='1.0.0',
    author='Mykola Grymalyuk',
    author_email='khronokernel@icloud.com',
    license='BSD 3-Clause License',
    description='Module for querying SIP status on XNU-based systems',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(exclude=('tests', 'docs')),
    url='https://github.com/khronokernel/py_sip_xnu',
    python_requires='>=2.7',
)