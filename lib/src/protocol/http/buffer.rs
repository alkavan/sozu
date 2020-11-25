use pool::{Checkout, Pool};
use pool_crate::Reset;
use std::cmp::{max, min};
use std::{fmt, io};

pub struct HttpBuffer {
    pub buffer_position: usize,
    pub parsed_position: usize,
    pub start_parsing_position: usize,
    pub buffer: Checkout,
}

impl HttpBuffer {
    pub fn with_buffer(buffer: Checkout) -> HttpBuffer {
        HttpBuffer {
            buffer_position: 0,
            parsed_position: 0,
            start_parsing_position: 0,
            buffer,
        }
    }

    pub fn invariant(&self) {
        debug_assert!(
            self.buffer_position <= self.parsed_position,
            "buffer_position {} should be smaller than parsed_position {}",
            self.buffer_position,
            self.parsed_position
        );
        /*debug_assert!(self.parsed_position <= self.start_parsing_position,
        "parsed_position {} should be smaller than start_parsing_position {}",
        self.parsed_position, self.start_parsing_position);*/
    }

    pub fn unparsed_data(&self) -> &[u8] {
        let start = std::cmp::min(
            self.buffer.available_data(),
            self.parsed_position - self.buffer_position,
        );

        &self.buffer.data()[start..]
    }

    pub fn consume_parsed_data(&mut self, size: usize) {
        self.parsed_position += size;
        //println!("consume_parsed_data");
    }
    /*
    pub fn sliced_input(&mut self, count: usize) {
        println!("sliced_input");
    }
    pub fn needs_input(&self) -> bool {
      self.start_parsing_position > self.parsed_position
    }
    pub fn can_restart_parsing(&self) -> bool {
      self.start_parsing_position == self.buffer_position
    }

    pub fn empty(&self) -> bool {
      //self.input_queue.is_empty() && self.output_queue.is_empty() && self.buffer.empty()
      unimplemented!()
    }

    pub fn consume_parsed_data(&mut self, size: usize) {
        println!("consume_parsed_data");
    }

    pub fn output_data_size(&self) -> usize {
        println!("output_data_size");
        0
    }

    pub fn next_output_data(&self) -> &[u8] {
        println!("next output data");
        &b""[..]
    }
    pub fn consume_output_data(&mut self, size: usize) {
        println!("consume output data");
    }
    */

    pub fn as_ioslice(&self) -> Vec<std::io::IoSlice> {
        /*let mut res = Vec::new();

        let it = self.output_queue.iter();
        //first, calculate how many bytes we need to jump
        let mut start         = 0usize;
        let mut largest_size  = 0usize;
        let mut delete_ended  = false;
        let length = self.buffer.available_data();
        //println!("NEXT OUTPUT DATA:\nqueue:\n{:?}\nbuffer:\n{}", self.output_queue, self.buffer.data().to_hex(16));
        let mut complete_size = 0;
        for el in it {
          match el {
            &OutputElement::Delete(sz) => start += sz,
            &OutputElement::Slice(sz)  => {
              //println!("Slice({})", sz);
              if sz == 0 {
                continue
              }
              let end = min(start+sz, length);
              let i = std::io::IoSlice::new(&self.buffer.data()[start..end]);
              //println!("iovec size: {}", i.len());
              res.push(i);
              complete_size += i.len();
              start = end;
              if end == length {
                break;
              }
            }
            &OutputElement::Insert(ref v) => {
              if v.is_empty() {
                continue
              }
              let i = std::io::IoSlice::new(&v[..]);
              //println!("got Insert with {} bytes", v.len());
              res.push(i);
              complete_size += i.len();
            },
            &OutputElement::Splice(sz)  => { unimplemented!("splice not used in ioslice") },
          }
        }

        //println!("returning iovec: {:?}", res);
        //println!("returning iovec with {} bytes", complete_size);
        res*/
        unimplemented!()
    }
}

impl io::Write for HttpBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.buffer.write(buf) {
            Err(e) => Err(e),
            Ok(sz) => {
                /*if sz > 0 {
                  self.input_queue.push(InputElement::Slice(sz));
                }*/
                Ok(sz)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Reset for HttpBuffer {
    fn reset(&mut self) {
        self.parsed_position = 0;
        self.buffer_position = 0;
        self.start_parsing_position = 0;
        self.buffer.reset();
    }
}

impl fmt::Debug for HttpBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //let b: &Buffer = &self.buffer;
        write!(f, "BufferQueue {{\nbuffer_position: {},\nparsed_position: {},\nstart_parsing_position: {},\nbuffer: {:?}\n}}",
      self.buffer_position, self.parsed_position, self.start_parsing_position,
       /*b*/ ())
    }
}

pub fn http_buf_with_capacity(capacity: usize) -> (Pool, HttpBuffer) {
    let mut pool = Pool::with_capacity(1, capacity, 16384);
    let b = HttpBuffer::with_buffer(pool.checkout().unwrap());
    (pool, b)
}
