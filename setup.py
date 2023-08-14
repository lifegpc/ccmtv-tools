import sys
from setuptools import Extension
from version import version, dversion

if "py2exe" in sys.argv:
    from distutils.core import setup
    import py2exe
    params = {
        "console": [{
            'script': "ccmtv/__main__.py",
            "dest_base": 'ccmtv',
            'version': version,
            'product_name': 'ccmtv',
            'product_version': dversion,
            'company_name': 'lifegpc',
            'description': 'CCMTV Tools',
        }],
        "options": {
            "py2exe": {
                "optimize": 2,
                "compressed": 1,
                "excludes": ["pydoc", "unittest"],
                "includes": ["charset_normalizer.md__mypyc"]
            }
        },
        "zipfile": None,
    }
else:
    from setuptools import setup
    from setuptools import setup
    params = {
        "install_requires": ["requests"],
        'entry_points': {
            'console_scripts': ['ccmtv = ccmtv:run']
        },
        "python_requires": ">=3.6"
    }
setup(
    name="ccmtv-tools",
    version=version,
    url="https://github.com/lifegpc/ccmtv-tools",
    author="lifegpc",
    author_email="root@lifegpc.com",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python :: 3.7",
    ],
    license="GNU General Public License v3 or later",
    description="CCMTV Tools",
    long_description="CCMTV Tools",
    keywords="tools",
    packages=["ccmtv"],
    **params
)
