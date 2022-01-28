About
-----
This tools keeps file encrypted with separate file headers. Let's create a backup on disk device:
```
xcbackup -c TestPassword_123 /dev/sdzzz dir1 dir2 file1
```
If only some sectors are gone, you should not loose other files in the backup, because each file is prefixed with byte sequence and has separate encryption header and separate file header located before its encrypted body. If a corrupted data sequence is found by checking HMAC, then the progranm will lookup for the nearest file prefix bytes sequence to extract the next file. In other words, writing a few random bytes at the beginning of backup file will result in losing only first files, but not whole backup.

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
