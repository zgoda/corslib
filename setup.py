import ast
import codecs
import re
from os import path

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))


def read(*parts):
    with codecs.open(path.join(here, *parts), 'r') as fp:
        return fp.read()


_version_re = re.compile(r"__version__\s+=\s+(.*)")


def find_version(*where):
    return str(ast.literal_eval(_version_re.search(read(*where)).group(1)))


base_reqs = [
    'dataclasses ; python_version < "3.7"'
]

test_reqs = [
    'pytest',
    'pytest-cov',
]

docs_reqs = [
    'Sphinx',
    'furo',
]

dev_reqs = [
    'ipython',
    'ipdb',
    'wheel',
    'flake8',
    'flake8-builtins',
    'flake8-bugbear',
    'flake8-comprehensions',
    'flake8-pytest-style',
    'pep8-naming',
    'dlint',
    'rstcheck',
    'rope',
    'isort',
] + test_reqs + docs_reqs

setup(
    name='corslib',
    version=find_version('src', 'corslib', '__init__.py'),
    author='Jarek Zgoda',
    author_email='jarek.zgoda@gmail.com',
    description='Policy-based CORS support library for web applications',
    keywords='cors wsgi',
    long_description=read('README.rst'),
    long_description_content_type='text/x-rst',
    license='BSD',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    url='http://github.com/zgoda/corslib',
    project_urls={
        'Documentation': 'https://corslib.readthedocs.io/',
        'Source': 'https://github.com/zgoda/corslib',
        'Issues': 'https://github.com/zgoda/corslib/issues',
    },
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    install_requires=base_reqs,
    extras_require={
        'dev': dev_reqs,
        'test': test_reqs,
        'docs': docs_reqs,
    },
    python_requires='~=3.6',
)
