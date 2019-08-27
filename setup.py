import os
from setuptools import setup

ABOUT = {}

with open(os.path.join(os.path.dirname(__file__), "tn3270", "__about__.py")) as file:
    exec(file.read(), ABOUT)

LONG_DESCRIPTION = """# pytn3270

Python TN3270 library.

See [GitHub](https://github.com/lowobservable/pytn3270#readme) for more information.
"""

setup(
    name='pytn3270',
    version=ABOUT['__version__'],
    description='TN3270 library',
    url='https://github.com/lowobservable/pytn3270',
    author='Andrew Kay',
    author_email='projects@ajk.me',
    packages=['tn3270'],
    install_requires=[],
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Communications',
        'Topic :: Terminals'
    ]
)
