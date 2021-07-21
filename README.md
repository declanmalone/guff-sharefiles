# guff-sharefiles
Package IDA-encoded data in a portable file format

First version doesn't implement the sharefile format, but
it does enough to generate some benchmarks.

Create a file with 16 MBytes + 8 bytes.

```ascii
$ dd if=/dev/urandom bs=1024 count=16384 of=16m
$ echo "\0\0\0\0\0\0\0\0" >> 16m
```

Then build the project with all optimisations turned on:

```ascii
$ RUSTFLAGS="-O -C target-cpu=native -C target-feature=+ssse3,+sse4.1,+sse4.2,+avx" cargo build
```

Can then compare this program with the `rabin-split.pl` script from my
original Perl implementation (`Crypt::IDA` on CPAN):

```ascii
$ time rabin-split.pl  -k 8 -n 16 -w 1 16m     # Perl/C
$ time ./target/debug/ida-split 16m            # rust simd mul
$ time ./target/debug/ida-split -r 16m         # rust reference mul
```

Results:

| rabin-split.pl | rust simd     | rust reference |
|real  0m0.935s  | real	0m1.456s | real	0m1.687s  |
|user  0m0.874s  | user	0m1.220s | user	0m1.596s  |
|sys   0m0.060s  | sys	0m0.069s | sys	0m0.056s  |

Overall, only around 65% the speed of the original version, even though
it has less overheads (not writing file headers, not multipliying blocks
of the file) and should have a faster multiply kernel.

Still, not bad as a starting point...
