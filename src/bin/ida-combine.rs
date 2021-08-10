//! Combine a set of IDA share files
//!

use guff_sharefiles::*;

use clap::{Arg, App};
use std::io;
use std::io::prelude::*;
use std::io::ErrorKind::*;
use std::fs::File;
use std::fs::metadata;
use std::convert::TryInto;

use guff::*;
use guff_matrix::*;
use guff_ida::*;

fn main() {

    let matches = App::new("ida-combine")
        .version("1.0")
        .author("Declan Malone <idablack@users.sourceforge.net>")
        .about("Rabin IDA combine")
         //   .usage("ida-combine infile1 [infile2 ...]")
	.args_from_usage(
            "-r                   'Use reference matrix mul'
             -s                   'Use SIMD matrix mul (default)'
             -o <FILE>            'Output file name (required)'")
	.arg(Arg::with_name("INFILE")
             .multiple(true)
	     .help("Sets the input file(s) to use")
	     .required(true)
	     .index(1))
        .get_matches();

    let use_ref = matches.is_present("r");

    // how do we specify a list of filenames?
    let files: Vec<_> = matches.values_of("INFILE").unwrap().collect();

    let mut xform_rows : Vec<_> = Vec::with_capacity(255);
    let mut handles : Vec<_> = Vec::with_capacity(255);
    
    // Get details of share scheme from first file
    let headers : Vec<HeaderV1> = Vec::with_capacity(255);

    let mut fh = File::open(files[0]).unwrap();
    let header = read_sharefile_header(&mut fh).unwrap();

    // after borrow, we can reuse fh
    handles.push(fh);

    let k = header.k;
    let w = header.w;
    let chunk_start = header.chunk_start;
    let chunk_next  = header.chunk_next;

    if files.len() < k {
        panic!("Not enough files supplied to satisfy quorum {}", k)
    }
    
    if w != 1 {
        panic!("Sorry, can't combine files with {}-byte fields yet", w);
    }
    if k + files.len() > 255 {
        panic!("(k,n) too large for 1-byte fields");
    }
    if chunk_start != 0 {
        panic!("Sorry, combining chunks not supported yet");
    }

    xform_rows.push(header.xform_data);


    // Scan remaining files
    for (index,file) in files.iter().enumerate() {
        if index == 0 { continue }

        if index >= k {
            eprintln!("File {} (and beyond) ignored as quorum reached",
            files[index]);
            break;
        }
        
        let mut fh = File::open(file).unwrap();
        let header = read_sharefile_header(&mut fh).unwrap();

        handles.push(fh);

        if header.w != w {
            panic!("Mismatched k value for file {}", file);
        }
        if header.k != k {
            panic!("Mismatched w value for file {}", file);
        }
        if header.chunk_start != chunk_start {
            panic!("Mismatched chunk_start value for file {}", file)
        }
        if header.chunk_next != chunk_next {
            panic!("Mismatched chunk_next value for file {}", file)
        }

        xform_rows.push(header.xform_data);
    }

    assert_eq!(xform_rows.len(), k);

    // Invert the matrix formed by the xform_rows
    let mut array = Vec::with_capacity(k * k * w);
    for row in xform_rows {
        array.extend(row)
    }
    assert_eq!(array.len(), k * k * w);

    // TODO: fix invert method so that the returned matrix has correct
    // guard section (including wrap-around data). For now, work
    // around by creating a new matrix and calling fill().

    let mut xform = Matrix::new(k,k,true);
    xform.fill(array.as_slice());
    let mut inv   = match xform.invert(&new_gf8(0x11b,0x1b)) {
        Some(m) => { m },
        _ => { panic!("No Matrix inverse (duplicate shares supplied?)") }
    };
        
    
}

