use coreshift_core::fs::readahead;
use std::fs::File;
use std::io::{Error, ErrorKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "usage: readahead_file <path>"))?;
    let file = File::open(&path)?;
    let len = file.metadata()?.len().min(128 * 1024) as usize;

    readahead(file, 0, len)?;
    println!("Requested readahead for {} bytes from {}", len, path);

    Ok(())
}
