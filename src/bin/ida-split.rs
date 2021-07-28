
use guff_sharefiles::*;

use clap::{Arg, App};
use std::io;
use std::io::prelude::*;
use std::io::ErrorKind::*;
use std::fs::{File};
use std::fs::metadata;
use std::convert::TryInto;

use guff::*;
use guff_matrix::*;
use guff_matrix::x86::*;
use guff_ida::*;

// file that 16384k + 8 bytes
const INFILE : &str = "16m";

// will split it using an 8,16 scheme
// producing share filess 2m.0, 2m.1, 2m.2, ... , 2m.15
//
// 

fn main() -> io::Result<()> {

    // After much faff, I discovered that cargo run was messing with
    // the filename that I was trying to pass. I assume it gobbled it
    // up itself?
    //
    // Need to use --bin AND --. For example:
    //
    // cargo run --bin ida-split -- -r foo
    
    let matches = App::new("ida-split")
        .version("1.0")
        .author("Declan Malone <idablack@users.sourceforge.net>")
        .about("Rabin IDA split")
    //        .usage("ida-split infile")
    //.arg(Arg::with_name("file").value_name("INFILE").required(false))
	.args_from_usage(
            "-r                   'Use reference matrix mul'
             -f                   'Slurp in full 16m +  8 byte file'
             -k=[int]             'quorum value'
             -n=[int]             'number of shares'
             -s                   'Use SIMD matrix mul (default)'")
	.arg(Arg::with_name("INFILE")
	     .help("Sets the input file to use")
	     .required(false)
	     .index(1))
        .get_matches();

    let infile = match matches.value_of("INFILE") {
	Some(f) => { println!("Using input file: {}", f);      f },
	_       => { println!("Using default file\n");    INFILE }
    };

    let k : usize = if let Some(num) = matches.value_of("k") {
	num.parse().unwrap()
    } else {
	8
    };

    let n : usize = if let Some(num) = matches.value_of("n") {
	num.parse().unwrap()
    } else {
	16
    };

    let use_ref = matches.is_present("r");

    if ! matches.is_present("f") {
	eprintln!("Doing block-wise split");
	return blockwise_split(infile, k, n, 8192, use_ref)
    }

    // full slurp only works for a test file of 16Mbytes + 8 bytes

    eprintln!("Doing full slurp");

    let mut input = File::open(infile)?;
    let mut buffer = vec![0; (16384*1024) + 8];

    // 16384 / 8 = 2048, so input and output matrices will have 2049
    // columns, satisfying gcd property.
    
    let got = input.read(&mut buffer.as_mut_slice())?;
    if got < (16384*1024) + 8 {
	eprintln!("Didn't read all of file");
	return Ok(())
    }

    // set up matrices
    let key = vec![ 1, 2, 3, 4, 5, 6, 7, 8,
		    9,10,11,12,13,14,15,16,
		    17,18,19,20,21,22,23,24];
    let field = new_gf8(0x11b, 0x1b);
    let cauchy_data = cauchy_matrix(&field, &key, 16, 8);


    // guff-matrix needs either/both/all:
    // * architecture-neutral matrix type (NoSimd option)
    // * automatic selection of arch-specific type (with fallback)
    // * new_matrix() type constructors?
    //
    // For now, though, the only concrete matrix types that are
    // implemented are for supporting x86 simd operation, so use
    // those (clunky) names...

    let mut xform = X86Matrix::<x86::X86u8x16Long0x11b>
	::new(16,8,true);
    xform.fill(&cauchy_data);

    // must choose cols appropriately (gcd requirement)
    let mut input = X86Matrix::<x86::X86u8x16Long0x11b>
	::new(8,2048 * 1024 + 1 ,false);
    input.fill(&buffer);

    let mut output = X86Matrix::<x86::X86u8x16Long0x11b>
	::new(16,2048 * 1024 + 1,true);

    // Choice of multiply routines


    if use_ref {
	reference_matrix_multiply(&mut xform, &mut input,
				  &mut output, &field);
    } else {
	unsafe {
	    simd_warm_multiply(&mut xform, &mut input, &mut output);
	}
    }

    // Output the 16 files
    let data = output.as_slice().chunks(2048 * 1024 + 1);
    for (ext, chunk) in data.enumerate() {
	let outfile = format!("{}-full.{}", infile, ext + 1);
	let mut f = File::create(outfile)?;
	f.write(chunk)?;
    }

    Ok(())
}

// Do the transform on a block-by-block basis
//
// Profiling the code shows that 36% of the time is spent in writing
// to the output matrix. That accounts for the biggest chunk of
// runtime. I don't know if the overhead here is being caused by
// Rust's bounds checks on the accesses, or whether it's something
// potentially worse: that the pattern of (fairly) random writes
// itself is the cause.
//
// I wrote my matrix multiply algorithm assuming that cache issues
// shouldn't be a problem for scattered writes, but perhaps it is.
//
// Anyway, I have to implement block-by-block processing of the file
// anyway. When it's done, it might shine a light on where the real
// bottleneck is. If it's cache write misses, then using smaller
// buffers should improve locality of reference at the expense of
// extra function calls and setup costs.
//
// Buffer size
//
// The multiply algorithm has restrictions on how many columns can be
// in the input/output matrices. So depending on k (eg, 4, 8), we
// might not be able to use some common power of 2 buffer
// sizes. However, when reading from files, it's best to read in a
// multiple of the file system's block size.
//
// What I will do is allocate an extra column, but not use it for
// storing values.

//
// Results...
//
// After fixing a bug in the *reference* multiply routine, I can
// confirm that the main bottleneck before was actually due to write
// cache misses. The blockwise split below produces the same output
// data, but without the bottlneck in writing to the output.
//
// Sample run data:
//
// Blockwise      Slurp
// -------------  --------------
// real 0m0.703s  real  0m1.218s
// user 0m0.581s  user  0m1.090s
// sys  0m0.048s  sys   0m0.085s
//

fn blockwise_split(infile : &str, k : usize, n : usize,
		   mut cols : usize, use_ref : bool)
		   -> io::Result<()> {

    // eprintln!("n+k = {}", n+k);
    let key_range = 1..;
    let key = key_range.take(n+k).collect();

    let field = new_gf8(0x11b, 0x1b);
    let cauchy_data = cauchy_matrix(&field, &key, n, k);

    // eprintln!("Cauchy matrix data: {:x?}", cauchy_data);

    // use larger matrix if we need to satisfy gcd condition but
    // remember that we shouldn't fill or use that column in the
    // input/output.
    let want_cols = cols;	// cols we want to I/O
    let mut gcd_padding = 0;
    if cols % k == 0 {
	cols += 1;		// actual matrix columns
	gcd_padding = k;
    }

    let mut read_handle = File::open(infile)?;
    // do we need a reader if we're loading big chunks of the file all
    // the time? Let's say "no" for now.
    // let mut reader = BufReader::new(read_handle);

    // also need to find file size...
    let file_size = metadata(infile)?.len();

    // We can get a mutable slice of the input matrix to avoid
    // allocating a new vector and copying it. We may have to drop it,
    // though, in order for the matrix multiply routine to borrow the
    // struct mutably.
    let mut xform = X86Matrix::<x86::X86u8x16Long0x11b>
	::new(n,k,true);
    xform.fill(&cauchy_data);

    // must choose cols appropriately (gcd requirement)
    let mut input = X86Matrix::<x86::X86u8x16Long0x11b>
	::new(k,cols ,false);
    // input.fill(&buffer); // filled in loop

    let mut output = X86Matrix::<x86::X86u8x16Long0x11b>
	::new(n,cols,true);

    // in preparation for writing share headers, break cauchy_data up
    // into per-share chunks.
    let cauchy_clone = cauchy_data.clone();
    let mut transform_chunks = cauchy_clone.chunks(k);

    // open the n output files and stash the handles
    let mut handles = Vec::with_capacity(n);
    for ext in 1..=n {
	let outfile = format!("{}-block.{}", infile, ext);
	let mut f = File::create(outfile)?;

	// slightly wasteful setting up new structs each time...
	let w = 1;
	let chunk_start = 0;
	let chunk_next = file_size.try_into().unwrap();
	let large_k = false;
	let large_w = false;
	let is_final = true;
	let xform = true;
	let xform_data = transform_chunks.next().unwrap().to_vec();
	let header = HeaderV1 {
	    k, w, chunk_start, chunk_next, large_k, large_w,
	    is_final, xform, xform_data };

	write_sharefile_header(&mut f, &header)?;

	handles.push(f);
    }

    // let mut wrote_data = 0;
    let mut at_eof = false;
    loop {
	let want_bytes = want_cols * k;
	let mut have_bytes = 0;

	// array has padding, but matrix doesn't expose it
	let mut slice = input.as_mut_slice();

	// we have to shrink slice if we added gcd padding
	if gcd_padding > 0 {
	    slice = &mut slice[..want_bytes]
	}

	while have_bytes < want_bytes {
	    let result = read_handle.read(&mut slice);
	    match result {
		Err(e) => {
		    if e.kind() == Interrupted {
			// apparently we just retry
			continue
		    } else {
			panic!("Some kind of I/O error: {}", e);
		    }
		},
		Ok(0) => { at_eof = true; break },
		Ok(n) => {
		    have_bytes += n;
		    slice = &mut slice[n..];
		    // loop again to see if we receive more
			
		},
	    }
	}
	// drop(slice); // not used again anyway

	// do the multiply on the block
	if use_ref {
	    reference_matrix_multiply(&mut xform, &mut input,
				      &mut output, &field);
	} else {
	    unsafe {
		simd_warm_multiply(&mut xform, &mut input, &mut output);
	    }
	}
	//	if simd_output.as_slice()[0] != ref_output.as_slice()[0] {
	//	    eprintln!("ref and simd differ after {}", wrote_data);
	//	}

	if have_bytes == 0 && at_eof {
	    eprintln!("File EOF found at even bufsize boundary");
	    return Ok(())
	}

	let mut output_cols = want_cols;
	if have_bytes > 0 && at_eof {
	    eprintln!("File EOF with {} bytes in final partial block",
		      have_bytes);
	    // round up to the next full column
	    if have_bytes % k != 0 {
		have_bytes += k - 1;
	    }
	    output_cols = have_bytes / k;
	}

	// write out to the n share files
	let data = output.as_slice().chunks(cols);
	for (ext, chunk) in data.enumerate() {
	    // eprintln!("ext: {}", ext);
            handles[ext].write(&chunk[..output_cols])?;
	}

	// wrote_data += output_cols;
	
	if at_eof { return Ok(()) }
    }

}

