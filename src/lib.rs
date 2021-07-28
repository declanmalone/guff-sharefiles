

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

use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;

use guff::*;

pub struct HeaderV1 {

    // magic and version elided
    pub k : usize,
    pub w : usize,

    pub chunk_start : usize,
    pub chunk_next  : usize,

    // for u16, u32, read/write xform_data as big-endian
    pub xform_data : Vec<u8>,

    // split options out
    pub large_k  : bool,
    pub large_w  : bool,
    pub is_final : bool,
    pub xform    : bool,
}

pub fn read_sharefile_header(_file : &mut File)
			 -> Result<HeaderV1,String>
{

    let k = 4;
    let w = 1;
    let chunk_start = 0;
    let chunk_next = 0;
    let large_k = false;
    let large_w = false;
    let is_final = true;
    let xform = true;
    let xform_data = vec![0u8; 14];
    
    Ok(HeaderV1 {
	k, w, chunk_start, chunk_next, large_k, large_w,
	is_final, xform, xform_data
    })
}			 

// variable encoding length:
//
// 0   -> 0
// 1   -> 1 1
// 255 -> 1 255
// 256 -> 2 1 0
// etc.
//
// <bytes> [<high> ... <low>]
pub fn encode_length(mut n : usize) -> Vec<u8> {
    // let old_n = n;
    let mut shifts = 0;
    let mut v = Vec::<u8>::with_capacity(8);
    while n > 0 {
	v.push(n as u8);
	n = n >> 8;
	shifts += 1;
    }
    v.push(shifts);
    v.reverse();
    // eprintln!("encoded {} as {:x?}", old_n, v);
    v
}

pub fn write_sharefile_header(file : &mut File, header : &HeaderV1)
			  -> Result<usize, std::io::Error>
{

    let mut buffer = Vec::<u8>::with_capacity(30);

    buffer.push('S' as u8);
    buffer.push('F' as u8);
    buffer.push(1);

    let mut options = 0;
    if header.large_k  { options |= 1 }
    if header.large_w  { options |= 2 }
    if header.is_final { options |= 4 }
    if header.xform    { options |= 8 }

    buffer.push(options);

    // everything is stored in big endian format
    if header.large_k {
	buffer.push(((header.k >> 8) & 255) as u8);
    }
    buffer.push((header.k & 255) as u8);

    if header.large_w {
	buffer.push(((header.w >> 8) & 255) as u8);
    }
    buffer.push((header.w & 255) as u8);

    buffer.extend(encode_length(header.chunk_start).iter());
    buffer.extend(encode_length(header.chunk_next).iter());

    buffer.extend(header.xform_data.iter());

    let length = buffer.len();
    // eprintln!("Buffer is of length {}", length);
    match file.write(&buffer) {
	Ok(n) => {
	    if n != length {
		Err(std::io::Error::new(
		    ErrorKind::Other, 
		    format!("Failed to write all {} header bytes",
			    length)))
	    } else {
		Ok(n)
	    }
	},
	Err(x) => { Err(x) },
    }
}
