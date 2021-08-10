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
use guff_matrix::simulator::*;
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
    
    // Need a field to do invert (+if using reference mul)
    let field = new_gf8(0x11b,0x1b);

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
    let mut inv   = match xform.invert(&field) {
        Some(m) => { m },
        _ => { panic!("No Matrix inverse (duplicate shares supplied?)") }
    };

    // All error-checking complete, so open output file
    let mut outfile = File::create(matches.value_of("o").unwrap()).unwrap();

    // work around invert not setting up guard properly
    let mut xform = Matrix::new(k,k,true);
    xform.fill(inv.as_slice());

    // Decide on an appropriate buffer size
    let mut bufsize = 16384;
    if bufsize % k == 0 {
        bufsize += 1
    }

    // block-wise combine
    //
    // chunk_next tells us how many bytes should be in the output
    // file. We will need to read chunk_next / k bytes (rounded up)
    // from each input file.

    // eprintln!("chunk_next is {}", chunk_next);
    let mut expect_read_bytes = chunk_next / k;
    if expect_read_bytes * k != chunk_next { // alternative to %
        expect_read_bytes += 1
    }

    // eprintln!("Expect to read {} bytes from each stream (hex: {:x})",
    //           expect_read_bytes, expect_read_bytes);


    // Set up other matrices.
    
    // The SIMD matrix multiply requires that the input matrix is in
    // colwise format, while the reference multiply is agnostic about
    // format. The output matrix can be in either format, but for
    // sequential output the most logical choice is colwise.
    //
    // This means that if we're using the reference multiply, we can
    // choose the layout that makes it easiest to populate the input
    // matrix, which is rowwise.
    //
    // If we're using the SIMD, we have no choice but to use colwise,
    // so we will need to interleave the input streams.

    let mut output = Matrix::new(k, bufsize, false);

    let mut input;
    if use_ref {
        input = Matrix::new(k, bufsize, true);
    } else {
        input = Matrix::new(k, bufsize, false);
    }

    // Set up read buffers. For reference multiply, these can be
    // slices of the input matrix, but we need temporary storage when
    // there's an interleave step.
    let mut temp_buffers = vec![0u8; k * bufsize * w];

    // expect_read_bytes is also the total number of columns that we
    // must process to produce all the output, so we can use it as our
    // loop counter/condition.
    let mut columns_processed = 0;
    // eprintln!("Expect to read {} bytes per input file",
    //           expect_read_bytes);
    while columns_processed < expect_read_bytes {

        // how many columns do we expect to process this time?
        let mut expect_columns = bufsize;
        if columns_processed + expect_columns > expect_read_bytes {
            // final block can be less than bufsize
            // eprintln!("Final (partial) block");
            expect_columns = expect_read_bytes - columns_processed
        }
        // eprintln!("processed: {}, expect {} this iteration",
        //           columns_processed, expect_columns);

        // read() needs mut slices, so set up a list of them
        let mut read_slices;// : Vec<&mut [u8]>;
        if use_ref {
            read_slices = input
                .as_mut_slice()
                .chunks_mut(bufsize)
            // .collect()
        } else {
            read_slices = temp_buffers
                .as_mut_slice()
                .chunks_mut(bufsize)
            // .collect()
        }

        // Assuming that read() can fail to return all requested bytes
        // sometimes (eg, due to interrupt), we need to loop over each
        // stream until the required number are returned. Persist with
        // one file until we get what we need or hit premature eof or
        // other unrecoverable error

        for (i, mut fh) in handles.iter().enumerate() {
            let mut got_columns = 0;
            let mut slice = read_slices.next().unwrap();
            let mut at_eof = false; // per-stream

            while got_columns < expect_columns {

                let result = fh.read(&mut slice);
	        match result {
	            Err(e) => {
		        if e.kind() == Interrupted {
		            // apparently we just retry
		            continue
		        } else {
		            panic!("I/O error on {}: {}", files[i], e);
		        }
	            },
	            Ok(0) => { at_eof = true; break },
	            Ok(n) => {
		        got_columns += n;
		        slice = &mut slice[n..];
		        // loop again to see if we receive more
		        
	            },
	        }
            }
            if at_eof && got_columns < expect_columns {
                panic!("Premature EOF on {}; got {}, expected {}",
                       files[i], got_columns, expect_columns)
            }
        }

        // drop(read_slices);      // might have a lock on matrix

        // do multiply
        if use_ref {
	    reference_matrix_multiply(&mut xform, &mut input,
				      &mut output, &field);
        } else {
            // TODO: add interleaver to main guff-matrix lib
            // The simulator module has a working version, so can use that
            // for now.

            let source_slices : Vec<_> = temp_buffers
                .as_slice()
                .chunks(bufsize)
                .collect();
            interleave_streams(input.as_mut_slice(), &source_slices);
	    unsafe {
	        simd_warm_multiply(&mut xform, &mut input, &mut output);
	    }
        }

        // Write out data
        outfile.write(&output.as_slice()[..expect_columns * k]);

        // actually ... above may put out too many bytes if original
        // input was not a multiple of k; can truncate the file so
        // that it's exactly chunk_next bytes (outside loop), or can
        // refine expect_columns * k value above.
        
        columns_processed += expect_columns;
    }
}

