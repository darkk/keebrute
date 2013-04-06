Brute-force application to tests passwords for KeePass kdb files, kdbx are not
supported. Only AES-encrypted files are supported at the moment.  Key-files are
not supported, but support for key-files is trivial to add.

The logic is deducted from file ``src/format/KeePass1Reader.cpp``
(KeepassX-2.0-alpha source code), so it inherits the license: GNU GPLv2 / GPLv3
