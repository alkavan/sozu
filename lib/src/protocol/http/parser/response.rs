use buffer_queue::BufferQueue;
use protocol::http::StickySession;

use nom::{HexDisplay,IResult,Offset,Err};

use std::str;
use std::convert::From;

use super::{BufferMove, LengthInformation, RStatusLine, Connection, Chunk, HeaderValue, TransferEncodingValue,
  Version, Header, message_header, status_line, crlf,};


pub type UpgradeProtocol = String;

#[derive(Debug,Clone,PartialEq)]
pub enum ResponseState {
  Initial,
  Error{status: Option<RStatusLine>, connection: Option<Connection>,
    upgrade: Option<UpgradeProtocol>, length: Option<LengthInformation>, chunk: Option<Chunk>},
  HasStatusLine{status: RStatusLine, connection: Connection},
  HasUpgrade{status: RStatusLine, connection: Connection, upgrade: UpgradeProtocol},
  HasLength{status: RStatusLine, connection: Connection, length: LengthInformation},
  Response{status: RStatusLine, connection: Connection},
  ResponseUpgrade{status: RStatusLine, connection: Connection, upgrade: UpgradeProtocol},
  ResponseWithBody{status: RStatusLine, connection: Connection, length: usize},
  ResponseWithBodyChunks{status: RStatusLine, connection: Connection, chunk: Chunk},
  // the boolean indicates if the backend connection is closed
  ResponseWithBodyCloseDelimited{status: RStatusLine, connection: Connection, back_closed: bool},
}

impl ResponseState {
  pub fn into_error(self) -> ResponseState {
    match self {
      ResponseState::Initial => ResponseState::Error{status: None, connection: None,
        upgrade: None, length: None, chunk: None},
      ResponseState::HasStatusLine{status, connection} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: None, length: None, chunk: None},
      ResponseState::HasLength{status, connection, length} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: None, length: Some(length), chunk: None},
      ResponseState::HasUpgrade{status, connection, upgrade} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: Some(upgrade), length: None, chunk: None},
      ResponseState::Response{status, connection} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: None, length: None, chunk: None},
      ResponseState::ResponseUpgrade{status, connection, upgrade} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: Some(upgrade), length: None, chunk: None},
      ResponseState::ResponseWithBody{status, connection, length} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: None, length: Some(LengthInformation::Length(length)), chunk: None},
      ResponseState::ResponseWithBodyChunks{status, connection, chunk} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: None, length: None, chunk: Some(chunk)},
      ResponseState::ResponseWithBodyCloseDelimited{status, connection, ..} =>
        ResponseState::Error{status: Some(status), connection:Some(connection),
          upgrade: None, length: None, chunk: None},
      err => err
    }
  }

  pub fn is_proxying(&self) -> bool {
    match *self {
        ResponseState::Response{..}
      | ResponseState::ResponseWithBody{..}
      | ResponseState::ResponseWithBodyChunks{..}
      | ResponseState::ResponseWithBodyCloseDelimited{..}
        => true,
      _ => false
    }
  }

  pub fn is_back_error(&self) -> bool {
    if let ResponseState::Error{..} = self {
      true
    } else {
      false
    }
  }

  pub fn get_status_line(&self) -> Option<&RStatusLine> {
    match self {
      ResponseState::HasStatusLine{status, ..}
      | ResponseState::HasLength{status, ..}
      | ResponseState::HasUpgrade{status, ..}
      | ResponseState::Response{status, ..}
      | ResponseState::ResponseUpgrade{status, ..}
      | ResponseState::ResponseWithBody{status, ..}
      | ResponseState::ResponseWithBodyCloseDelimited{status, ..}
      | ResponseState::ResponseWithBodyChunks{status, ..}=> Some(status),
      ResponseState::Error{status, ..} => status.as_ref(),
      _ => None,
    }
  }

  pub fn get_keep_alive(&self) -> Option<Connection> {
    match self {
      ResponseState::HasStatusLine{connection, ..}
      | ResponseState::HasLength{connection, ..}
      | ResponseState::HasUpgrade{connection, ..}
      | ResponseState::Response{connection, ..}
      | ResponseState::ResponseUpgrade{connection, ..}
      | ResponseState::ResponseWithBody{connection, ..}
      | ResponseState::ResponseWithBodyCloseDelimited{connection, ..}
      | ResponseState::ResponseWithBodyChunks{connection, ..} => Some(connection.clone()),
      ResponseState::Error{connection, ..} => connection.clone(),
      _  => None,
    }
  }

  pub fn get_mut_connection(&mut self) -> Option<&mut Connection> {
    match self {
      ResponseState::HasStatusLine{connection, ..}
      | ResponseState::HasLength{connection, ..}
      | ResponseState::HasUpgrade{connection, ..}
      | ResponseState::Response{connection, ..}
      | ResponseState::ResponseUpgrade{connection, ..}
      | ResponseState::ResponseWithBody{connection, ..}
      | ResponseState::ResponseWithBodyCloseDelimited{connection, ..}
      | ResponseState::ResponseWithBodyChunks{connection, ..} => Some(connection),
      ResponseState::Error{connection, ..} => connection.as_mut(),
      _ => None
    }
  }

  pub fn should_copy(&self, position: usize) -> Option<usize> {
    match *self {
      ResponseState::ResponseWithBody{length,..} => Some(position + length),
      ResponseState::Response{..} => Some(position),
      _ => None
    }
  }

  pub fn should_keep_alive(&self) -> bool {
    //FIXME: should not clone here
    let sl = self.get_status_line();
    let version = sl.as_ref().map(|sl| sl.version);
    let conn = self.get_keep_alive();
    match (version, conn.map(|c| c.keep_alive)) {
      (_, Some(Some(true)))   => true,
      (_, Some(Some(false)))  => false,
      (Some(Version::V10), _) => false,
      (Some(Version::V11), _) => true,
      (_, _)                  => false,
    }
  }

  pub fn should_chunk(&self) -> bool {
    if let  ResponseState::ResponseWithBodyChunks{..} = *self {
      true
    } else {
      false
    }
  }
}

pub fn default_response_result<O>(state: ResponseState, res: IResult<&[u8], O>) -> (BufferMove, ResponseState) {
  match res {
    Err(Err::Error(_)) | Err(Err::Failure(_)) => (BufferMove::None, state.into_error()),
    Err(Err::Incomplete(_)) => (BufferMove::None, state),
    _ => unreachable!()
  }
}

pub fn validate_response_header(mut state: ResponseState, header: &Header, is_head: bool) -> ResponseState {
  match header.value() {
    HeaderValue::ContentLength(sz) => {
      match state {
        // if the request has a HEAD method, we don't count the content length
        // FIXME: what happens if multiple content lengths appear?
        ResponseState::HasStatusLine{status, connection} => if is_head {
          ResponseState::HasStatusLine{status, connection}
        } else {
          ResponseState::HasLength{status, connection, length: LengthInformation::Length(sz)}
        },
        s => s.into_error(),
      }
    },
    HeaderValue::Encoding(TransferEncodingValue::Chunked) => {
      match state {
        ResponseState::HasStatusLine{status, connection} => if is_head {
          ResponseState::HasStatusLine{status, connection}
        } else {
          ResponseState::HasLength{status, connection, length: LengthInformation::Chunked}
        },
        s => s.into_error(),
      }
    },
    // FIXME: for now, we don't remember if we cancel indications from a previous Connection Header
    HeaderValue::Connection(c) => {
      if state.get_mut_connection().map(|conn| {
        if c.has_close {
          conn.keep_alive = Some(false);
        }
        if c.has_keep_alive {
          conn.keep_alive = Some(true);
        }
        if c.has_upgrade {
          conn.has_upgrade = true;
        }
      }).is_some() {
        if let ResponseState::HasUpgrade{status, connection, upgrade} = state {
          if connection.has_upgrade {
            ResponseState::HasUpgrade{status, connection, upgrade}
          } else {
            ResponseState::Error{status: Some(status), connection: Some(connection),
              upgrade: Some(upgrade), length: None, chunk: None}
          }
        } else {
          state
        }
      } else {
        state.into_error()
      }
    },
    HeaderValue::Upgrade(protocol) => {
      let proto = str::from_utf8(protocol).expect("the parsed protocol should be a valid utf8 string").to_string();
      trace!("parsed a protocol: {:?}", proto);
      trace!("state is {:?}", state);
      match state {
        ResponseState::HasStatusLine{status, mut connection} => {
          connection.upgrade = Some(proto.clone());
          ResponseState::HasUpgrade{status, connection, upgrade: proto}
        },
        s => s.into_error(),
      }
    }

    // FIXME: there should be an error for unsupported encoding
    HeaderValue::Encoding(_) => state,
    HeaderValue::Host(_)     => state.into_error(),
    HeaderValue::Forwarded(_)  => state.into_error(),
    HeaderValue::XForwardedFor(_) => state.into_error(),
    HeaderValue::XForwardedProto => state.into_error(),
    HeaderValue::XForwardedPort  => state.into_error(),
    HeaderValue::Other(_,_)  => state,
    HeaderValue::ExpectContinue => {
      // we should not get that one from the server
      state.into_error()
    },
    HeaderValue::Cookie(_)   => state,
    HeaderValue::Error       => state.into_error()
  }
}

pub fn parse_response(state: ResponseState, buf: &[u8], is_head: bool, sticky_name: &str, app_id: Option<&str>) -> (BufferMove, ResponseState) {
  match state {
    ResponseState::Initial => {
      match status_line(buf) {
        Ok((i, r))    => {
          if let Some(status) = RStatusLine::from_status_line(r) {
            let connection = Connection::new();
            /*let conn = if rl.version == "11" {
              Connection::keep_alive()
            } else {
              Connection::close()
            };
            */
            (BufferMove::Advance(buf.offset(i)), ResponseState::HasStatusLine{status, connection})
          } else {
            (BufferMove::None, ResponseState::Error{status: None, connection: None,
              upgrade: None, length: None, chunk: None})
          }
        },
        res => default_response_result(state, res)
      }
    },
    ResponseState::HasStatusLine{status, connection} => {
      match message_header(buf) {
        Ok((i, header)) => {
          let mv = if header.should_delete(&connection, sticky_name) {
            BufferMove::Delete(buf.offset(i))
          } else {
            BufferMove::Advance(buf.offset(i))
          };
          (mv, validate_response_header(ResponseState::HasStatusLine{status, connection}, &header, is_head))
        },
        Err(Err::Incomplete(_)) => (BufferMove::None, ResponseState::HasStatusLine{status, connection}),
        Err(_)      => {
          match crlf(buf) {
            Ok((i, _)) => {
              debug!("PARSER\theaders parsed, stopping");
              // no content
              if is_head ||
                // all 1xx responses
                status.status / 100  == 1 || status.status == 204 || status.status == 304 {
                (BufferMove::Advance(buf.offset(i)), ResponseState::Response{status, connection})
              } else {
                // no length information, so we'll assume that the response ends when the connection is closed
                (BufferMove::Advance(buf.offset(i)),
                  ResponseState::ResponseWithBodyCloseDelimited{status, connection, back_closed: false})
              }
            },
            res => {
              error!("PARSER\tHasStatusLine could not parse header for input(app={:?}):\n{}\n", app_id, buf.to_hex(16));
              default_response_result(ResponseState::HasStatusLine{status, connection}, res)
            }
          }
        }
      }
    },
    ResponseState::HasLength{status, connection, length} => {
      match message_header(buf) {
        Ok((i, header)) => {
          let mv = if header.should_delete(&connection, sticky_name) {
            BufferMove::Delete(buf.offset(i))
          } else {
            BufferMove::Advance(buf.offset(i))
          };
          (mv, validate_response_header(ResponseState::HasLength{status, connection, length}, &header, is_head))
        },
        Err(Err::Incomplete(_)) => (BufferMove::None, ResponseState::HasLength{status, connection, length}),
        Err(_)      => {
          match crlf(buf) {
            Ok((i, _)) => {
              debug!("PARSER\theaders parsed, stopping");
                match length {
                  LengthInformation::Chunked => (BufferMove::Advance(buf.offset(i)), ResponseState::ResponseWithBodyChunks{status, connection, chunk: Chunk::Initial}),
                  LengthInformation::Length(sz) => (BufferMove::Advance(buf.offset(i)), ResponseState::ResponseWithBody{status, connection, length: sz}),
                }
            },
            res => {
              error!("PARSER\tHasLength could not parse header for input(app={:?}):\n{}\n", app_id, buf.to_hex(16));
              default_response_result(ResponseState::HasLength{status, connection, length}, res)
            }
          }
        }
      }
    },
    ResponseState::HasUpgrade{status, connection, upgrade} => {
      match message_header(buf) {
        Ok((i, header)) => {
          let mv = if header.should_delete(&connection, sticky_name) {
            BufferMove::Delete(buf.offset(i))
          } else {
            BufferMove::Advance(buf.offset(i))
          };
          (mv, validate_response_header(ResponseState::HasUpgrade{status, connection, upgrade}, &header, is_head))
        },
        Err(Err::Incomplete(_)) => (BufferMove::None, ResponseState::HasUpgrade{status, connection, upgrade}),
        Err(_)      => {
          match crlf(buf) {
            Ok((i, _)) => {
              debug!("PARSER\theaders parsed, stopping");
              (BufferMove::Advance(buf.offset(i)), ResponseState::ResponseUpgrade{status, connection, upgrade})
            },
            res => {
              error!("PARSER\tHasUpgrade could not parse header for input(app={:?}):\n{}\n", app_id, buf.to_hex(16));
              default_response_result(ResponseState::HasUpgrade{status, connection, upgrade}, res)
            }
          }
        }
      }
    },
    ResponseState::ResponseWithBodyChunks{status, connection, chunk} => {
      let (advance, chunk) = chunk.parse(buf);
      (advance, ResponseState::ResponseWithBodyChunks{status, connection, chunk})
    },
    ResponseState::ResponseWithBodyCloseDelimited{status, connection, back_closed} => {
      (BufferMove::Advance(buf.len()), ResponseState::ResponseWithBodyCloseDelimited{status, connection, back_closed})
    },
    _ => {
      error!("PARSER\tunimplemented state: {:?}", state);
      (BufferMove::None, state.into_error())
    }
  }
}

pub fn parse_response_until_stop(mut current_state: ResponseState, mut header_end: Option<usize>,
  buf: &mut BufferQueue, is_head: bool, added_res_header: &str,
  sticky_name: &str, sticky_session: Option<&StickySession>, app_id: Option<&str>)
-> (ResponseState, Option<usize>) {
  loop {
    //trace!("PARSER\t{}\tpos[{}]: {:?}", request_id, position, current_state);
    let (mv, new_state) = parse_response(current_state, buf.unparsed_data(), is_head, sticky_name, app_id);
    //trace!("PARSER\tinput:\n{}\nmv: {:?}, new state: {:?}\n", buf.unparsed_data().to_hex(16), mv, new_state);
    //trace!("PARSER\t{}\tmv: {:?}, new state: {:?}\n", request_id, mv, new_state);
    current_state = new_state;

    match mv {
      BufferMove::Advance(sz) => {
        assert!(sz != 0, "buffer move should not be 0");

        // header_end is some if we already parsed the headers
        if header_end.is_none() {
          match current_state {
            ResponseState::Response{..}
            | ResponseState::ResponseUpgrade{..}
            | ResponseState::ResponseWithBodyChunks{..} => {
              buf.insert_output(Vec::from(added_res_header.as_bytes()));
              add_sticky_session_to_response(buf, sticky_name, sticky_session);

              buf.consume_parsed_data(sz);
              header_end = Some(buf.start_parsing_position);

              buf.slice_output(sz);
            },
            ResponseState::ResponseWithBody{length, ..} => {
              buf.insert_output(Vec::from(added_res_header.as_bytes()));
              add_sticky_session_to_response(buf, sticky_name, sticky_session);

              buf.consume_parsed_data(sz);
              header_end = Some(buf.start_parsing_position);

              buf.slice_output(sz+length);
              buf.consume_parsed_data(length);
            },
            ResponseState::ResponseWithBodyCloseDelimited{ref connection, ..} => {
              buf.insert_output(Vec::from(added_res_header.as_bytes()));
              add_sticky_session_to_response(buf, sticky_name, sticky_session);

              // special case: some servers send responses with no body,
              // no content length, and Connection: close
              // since we deleted the Connection header, we'll add a new one
              if connection.keep_alive == Some(false) {
                buf.insert_output(Vec::from(&b"Connection: close\r\n"[..]));
              }

              buf.consume_parsed_data(sz);
              header_end = Some(buf.start_parsing_position);

              buf.slice_output(sz);

              let len = buf.available_input_data();
              buf.consume_parsed_data(len);
              buf.slice_output(len);
            },
            _ => {
              buf.consume_parsed_data(sz);
              buf.slice_output(sz);
            }
          }
        } else {
          buf.consume_parsed_data(sz);
          buf.slice_output(sz);
        }
        //FIXME: if we add a slice here, we will get a first large slice, then a long list of buffer size slices added by the slice_input function
      },
      BufferMove::Delete(length) => {
        buf.consume_parsed_data(length);
        if header_end.is_none() {
          match current_state {
            ResponseState::Response{..}
            | ResponseState::ResponseUpgrade{..}
            | ResponseState::ResponseWithBodyChunks{..} => {
              //println!("FOUND HEADER END (delete):{}", buf.start_parsing_position);
              header_end = Some(buf.start_parsing_position);
              buf.insert_output(Vec::from(added_res_header.as_bytes()));
              add_sticky_session_to_response(buf, sticky_name, sticky_session);

              buf.delete_output(length);
            },
            ResponseState::ResponseWithBody{length, ..} => {
              header_end = Some(buf.start_parsing_position);
              buf.insert_output(Vec::from(added_res_header.as_bytes()));
              buf.delete_output(length);

              add_sticky_session_to_response(buf, sticky_name, sticky_session);

              buf.slice_output(length);
              buf.consume_parsed_data(length);
            },
            _ => {
              buf.delete_output(length);
            }
          }
        } else {
          buf.delete_output(length);
        }
      },
      _ => break
    }

    match current_state {
      ResponseState::Error{..} => {
        incr!("http1.parser.response.error");
        break;
      }
      ResponseState::Response{..} | ResponseState::ResponseWithBody{..} |
        ResponseState::ResponseUpgrade{..} |
        ResponseState::ResponseWithBodyChunks{chunk: Chunk::Ended, ..} |
        ResponseState::ResponseWithBodyCloseDelimited{..} => break,
      _ => ()
    }
    //println!("move: {:?}, new state: {:?}, input_queue {:?}, output_queue: {:?}", mv, current_state, buf.input_queue, buf.output_queue);
  }

  //println!("end state: {:?}, input_queue {:?}, output_queue: {:?}", current_state, buf.input_queue, buf.output_queue);
  (current_state, header_end)
}

fn add_sticky_session_to_response(buf: &mut BufferQueue,
  sticky_name: &str, sticky_session: Option<&StickySession>) {
  if let Some(ref sticky_backend) = sticky_session {
    let sticky_cookie = format!("Set-Cookie: {}={}; Path=/\r\n", sticky_name, sticky_backend.sticky_id);
    buf.insert_output(Vec::from(sticky_cookie.as_bytes()));
  }
}
