//! Display header information
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
         //   .usage("ida-header infile")
	.arg(Arg::with_name("INFILE")
	     .help("Sets the input file(s) to use")
	     .required(true)
	     .index(1))
        .get_matches();

    let file = matches.value_of("INFILE").unwrap();

    let mut fh = File::open(file).unwrap();
    let header = read_sharefile_header(&mut fh).unwrap();

    println!("File {} sharefile header info", file);
    println!("quorum (k)  = {}", header.k);
    println!("width  (w)  = {}", header.w);
    println!("chunk_start = {}", header.chunk_start);
    println!("chunk_next  = {}", header.chunk_next);
    if header.xform {
        println!("Header has embedded xform row:");
        println!("{:x?}", header.xform_data);
    } else {        
        println!("Header has no embedded xform row");
    }
}

