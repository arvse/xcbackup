About
-----
This tools keeps file encrypted with separate file headers.

For example let's create a backup on disk device:

```
xcbackup -c TestPassword_123 /dev/sdzzz dir1 dir2 file1
```

If some sectors are gone, you should not loose other files,

because each file is prefixed with byte sequence and

has its own encryption header and file header before its body.

If a corrupted data sequence is found, then the progranm

will lookup for nearest file prefix bytes found.

Usage
-----
```
usage: xcbackup -cxts stdin|password archive path [paths...]

version: 2.0.11

options:
  -c    create new archive
  -x    extract archive
  -t    test archive checksums
  -s    do not print progress

```

Building
--------
Install mbedtls then run make
