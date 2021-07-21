
use clap::{Arg, App, SubCommand};
use std::io;
use std::io::prelude::*;
use std::fs::File;

use guff::*;
use guff_matrix::*;
use guff_matrix::x86::*;
use guff_ida::*;

// file that 16384 + 8 bytes
const INFILE : &str = "16m";

// will split it using an 8,16 scheme
// producing share filess 2m.1, 2m.2, ... , 2m.16
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
            -s                    'Use SIMD matrix mul (default)'")
	.arg(Arg::with_name("INFILE")
	     .help("Sets the input file to use")
	     .required(false)
	     .index(1))
        .get_matches();

    let mut infile = match matches.value_of("INFILE") {
	Some(f) => { println!("Using input file: {}", f); f },
	_ => { println!("Using default file\n"); INFILE }
    };
    
    let mut input = File::open(infile)?;
    let mut buffer = vec![0; (16384*1024) + 8];

    // 16384 / 8 = 2048, so input and output matrices will have 2049
    // columns, satisfying gcd property.
    
    let n = input.read(&mut buffer.as_mut_slice())?;
    if n < (16384*1024) + 8 {
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

    let mut xform = X86SimpleMatrix::<x86::X86u8x16Long0x11b>
	::new(16,8,true);
    xform.fill(&cauchy_data);

    // must choose cols appropriately (gcd requirement)
    let mut input = X86SimpleMatrix::<x86::X86u8x16Long0x11b>
	::new(8,2048 * 1024 + 1 ,false);
    input.fill(&buffer);

    let mut output = X86SimpleMatrix::<x86::X86u8x16Long0x11b>
	::new(16,2048 * 1024 + 1,true);

    // Choice of multiply routines

    let use_ref = matches.is_present("r");

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
	let outfile = format!("{}.{}", infile, ext);
	let mut f = File::create(outfile)?;
	f.write(chunk)?;
    }

    
    Ok(())


	
}
