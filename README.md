# RAD - RunAsDate

This is a simple command-line version of RunAsDate.

I was interested in finding out how the original did its patchwork and thus I reverse-engineered it and reimplemented it.

It is more limited in terms of functionality, as it only supports immediate patching of the date and time.

Once compiled, the program can be run with these parameters:

```
RADCLI.exe <path to target program .exe> <day> <month> <year> <hour> <minute> <second> <0/1 - 0: do not advance clock, 1: advance custom time with the system clock>
```
