# Copyright 2016 Cedric Mesnil, Ubinity SAS

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
from distutils.core import setup

if  sys.version_info[0] == 2 and sys.version_info[1] < 7:
    sys.exit("Sorry, Python 2.7 or higher (included 3.x) is only supported ")

with open('README.md') as file:
    long_description = file.read()

setup(
    name             = 'ECPy',
    version          = '0.10.0',
    description      = 'Pure Pyhton Elliptic Curve Library',
    long_description = long_description,
    long_description_content_type = "text/markdown",
    keywords         = 'ecdsa eddsa ed25519 ed448 schnorr elliptic curve',
    author           = 'Cedric Mesnil',
    author_email     = 'cslashm@gmail.com',
    url              = 'https://github.com/cslashm/ECPy',
    license          = 'Apache License - Version 2.0',
    provides         = ['ecpy'],
    packages         = ['ecpy', 'ecpy.bip_schnorr'],
    package_dir      = {'ecpy': 'src/ecpy', 'ecpy.bip_schnorr':'src/ecpy/bip_schnorr'},
    install_requires = ["future"] if sys.version_info[0] < 3 else [],
    classifiers      = [
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Topic :: Security :: Cryptography'
    ]
)
