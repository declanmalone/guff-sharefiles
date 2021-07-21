

// Sharefile format compatible with those used in Crypt::IDA (Perl
// module on CPAN).

//  header version 1
// 
// bytes  name         value
// 2      magic        marker for "Share File" format; "SF" = {53,46}
// 1      version      file format version = 1
// 1      options      options bits (see below)
// 1-2    k,quorum     quorum k-value (set both names on read)
// 1-2    s,security   security level s-value (width in bytes)
// var    chunk_start  absolute offset of chunk in file
// var    chunk_next   absolute offset of next chunk in file
// var    transform    transform matrix row
// 
// The options bits are as follows:
// 
// Bit    name           Settings
// 0      opt_large_k    Large (2-byte) k value?
// 1      opt_large_w    Large (2-byte) s value?
// 2      opt_final      Final chunk in file? (1=full file/final chunk)
// 3      opt_transform  Is transform data included?
// 
// Note that the chunk_next field is 1 greater than the actual offset
// of the chunk end. In other words, the chunk ranges from the byte
// starting at chunk_start up to, but not including the byte at
// chunk_next. That's why it's called chunk_next rather than
// chunk_end.

