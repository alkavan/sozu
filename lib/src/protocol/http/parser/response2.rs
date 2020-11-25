use buffer_queue::BufferQueue;
use protocol::http::StickySession;

use nom::{Err, HexDisplay, IResult, Offset};

use std::convert::From;
use std::str;

use super::{
    crlf, message_header, BufferMove, Chunk, Connection, HeaderValue, LengthInformation,
    RStatusLine, TransferEncodingValue,
};

use super::header::{
    self, status_line, CopyingSlice, Header, HeaderName, Meta, Slice, StatusLine, Version,
};
use super::super::buffer::HttpBuffer;

pub type UpgradeProtocol = String;

#[derive(Debug, Clone, PartialEq)]
pub enum ResponseState {
    Initial,
    Error {
        status: Option<StatusLine>,
        headers: Vec<Header>,
        data: Option<Slice>,
        index: usize,
        upgrade: Option<UpgradeProtocol>,
        connection: Option<Connection>,
        length: Option<LengthInformation>,
        chunk: Option<Chunk>,
    },
    // index is how far we have parsed in the buffer
    Parsing {
        status: StatusLine,
        headers: Vec<Header>,
        index: usize,
    },
    ParsingDone {
        status: StatusLine,
        headers: Vec<Header>,
        /// start of body
        data: Slice,
        /// position of end of headers
        index: usize,
    },
    CopyingHeaders {
        status: Option<RStatusLine>,
        headers: Vec<Header>,
        data: Slice,
        index: usize,
        connection: Connection,
        upgrade: Option<UpgradeProtocol>,
        length: Option<LengthInformation>,
        header_slices: Vec<CopyingSlice>,
    },
    Response {
        status: RStatusLine,
        connection: Connection,
    },
    ResponseUpgrade {
        status: RStatusLine,
        connection: Connection,
        upgrade: UpgradeProtocol,
    },
    ResponseWithBody {
        status: RStatusLine,
        connection: Connection,
        length: usize,
    },
    ResponseWithBodyChunks {
        status: RStatusLine,
        connection: Connection,
        chunk: Chunk,
    },
    // the boolean indicates if the backend connection is closed
    ResponseWithBodyCloseDelimited {
        status: RStatusLine,
        connection: Connection,
        back_closed: bool,
    },
}

impl ResponseState {
    pub fn into_error(self) -> ResponseState {
        match self {
            ResponseState::Initial => ResponseState::Error {
                status: None,
                headers: Vec::new(),
                data: None,
                index: 0,
                upgrade: None,
                connection: None,
                length: None,
                chunk: None,
            },
            ResponseState::Parsing {
                status,
                headers,
                index,
            } => ResponseState::Error {
                status: Some(status),
                headers,
                data: None,
                index,
                upgrade: None,
                connection: None,
                length: None,
                chunk: None,
            },
            ResponseState::ParsingDone {
                status,
                headers,
                data,
                index,
            } => ResponseState::Error {
                status: Some(status),
                headers,
                data: Some(data),
                index,
                upgrade: None,
                connection: None,
                length: None,
                chunk: None,
            },
            ResponseState::Response { status, connection } => ResponseState::Error {
                status: None,
                headers: Vec::new(),
                data: None,
                index: 0,
                connection: Some(connection),
                upgrade: None,
                length: None,
                chunk: None,
            },
            ResponseState::ResponseUpgrade {
                status,
                connection,
                upgrade,
            } => ResponseState::Error {
                status: None,
                headers: Vec::new(),
                data: None,
                index: 0,
                connection: Some(connection),
                upgrade: Some(upgrade),
                length: None,
                chunk: None,
            },
            ResponseState::ResponseWithBody {
                status,
                connection,
                length,
            } => ResponseState::Error {
                status: None,
                headers: Vec::new(),
                data: None,
                index: 0,
                connection: Some(connection),
                upgrade: None,
                length: Some(LengthInformation::Length(length)),
                chunk: None,
            },
            ResponseState::ResponseWithBodyChunks {
                status,
                connection,
                chunk,
            } => ResponseState::Error {
                status: None,
                headers: Vec::new(),
                data: None,
                index: 0,
                connection: Some(connection),
                upgrade: None,
                length: None,
                chunk: Some(chunk),
            },
            ResponseState::ResponseWithBodyCloseDelimited {
                status, connection, ..
            } => ResponseState::Error {
                status: None,
                headers: Vec::new(),
                data: None,
                index: 0,
                connection: Some(connection),
                upgrade: None,
                length: None,
                chunk: None,
            },
            err => err,
        }
    }

    pub fn is_proxying(&self) -> bool {
        match *self {
            ResponseState::Response { .. }
            | ResponseState::ResponseWithBody { .. }
            | ResponseState::ResponseWithBodyChunks { .. }
            | ResponseState::ResponseWithBodyCloseDelimited { .. } => true,
            _ => false,
        }
    }

    pub fn is_back_error(&self) -> bool {
        if let ResponseState::Error { .. } = self {
            true
        } else {
            false
        }
    }

    pub fn get_status_line(&self) -> Option<&RStatusLine> {
        match self {
            ResponseState::Response { status, .. }
            | ResponseState::ResponseUpgrade { status, .. }
            | ResponseState::ResponseWithBody { status, .. }
            | ResponseState::ResponseWithBodyCloseDelimited { status, .. }
            | ResponseState::ResponseWithBodyChunks { status, .. } => Some(status),
            ResponseState::Error { status, .. } => None,
            _ => None,
        }
    }

    pub fn get_keep_alive(&self) -> Option<Connection> {
        match self {
            ResponseState::Response { connection, .. }
            | ResponseState::ResponseUpgrade { connection, .. }
            | ResponseState::ResponseWithBody { connection, .. }
            | ResponseState::ResponseWithBodyCloseDelimited { connection, .. }
            | ResponseState::ResponseWithBodyChunks { connection, .. } => Some(connection.clone()),
            ResponseState::Error { connection, .. } => connection.clone(),
            _ => None,
        }
    }

    pub fn get_mut_connection(&mut self) -> Option<&mut Connection> {
        match self {
            ResponseState::Response { connection, .. }
            | ResponseState::ResponseUpgrade { connection, .. }
            | ResponseState::ResponseWithBody { connection, .. }
            | ResponseState::ResponseWithBodyCloseDelimited { connection, .. }
            | ResponseState::ResponseWithBodyChunks { connection, .. } => Some(connection),
            ResponseState::Error { connection, .. } => connection.as_mut(),
            _ => None,
        }
    }

    pub fn should_copy(&self, position: usize) -> Option<usize> {
        match *self {
            ResponseState::ResponseWithBody { length, .. } => Some(position + length),
            ResponseState::Response { .. } => Some(position),
            _ => None,
        }
    }

    pub fn should_keep_alive(&self) -> bool {
        //FIXME: should not clone here
        let sl = self.get_status_line();
        let version = sl.as_ref().map(|sl| sl.version);
        let conn = self.get_keep_alive();
        match (version, conn.map(|c| c.keep_alive)) {
            (_, Some(Some(true))) => true,
            (_, Some(Some(false))) => false,
            (Some(super::Version::V10), _) => false,
            (Some(super::Version::V11), _) => true,
            (_, _) => false,
        }
    }

    pub fn should_chunk(&self) -> bool {
        if let ResponseState::ResponseWithBodyChunks { .. } = *self {
            true
        } else {
            false
        }
    }

    pub fn as_ioslice<'a,'b>(&'b self, buffer: &'a[u8]) -> Vec<std::io::IoSlice<'a>> {
        let mut v = Vec::new();

        match *self {
            ResponseState::CopyingHeaders { ref header_slices, .. } => {
                for h in header_slices.iter() {
                    match h {
                        CopyingSlice::Static(s) => v.push(std::io::IoSlice::new(*s)),
                        CopyingSlice::Slice(s) => match s.data(buffer){
                            Some(data) => v.push(std::io::IoSlice::new(data)),
                            None => break,
                        },
                    }
                }
            },
            ResponseState::ResponseWithBody { length, .. } => {
                let sz = std::cmp::min(length, buffer.len());
                v.push(std::io::IoSlice::new(&buffer[..sz]));
            },
            _ => unimplemented!(),
        }
        v
    }

    pub fn next_slice<'a>(&self, buffer: &'a [u8]) -> &'a [u8] {
        match *self {
            ResponseState::CopyingHeaders { ref header_slices, .. } => {
                header_slices.get(0).and_then(|h| match h {
                    CopyingSlice::Static(s) => Some(*s),
                    CopyingSlice::Slice(s) => s.data(buffer),
                }).unwrap_or(&b""[..])
            },
            ResponseState::Response{..} => &b""[..],
            ResponseState::ResponseWithBody { length, .. } => {
                let sz = std::cmp::min(length, buffer.len());
                &buffer[..sz]
            }
            /*
            RequestState::RequestWithBody(request_line, connection, host, sz) => {
                false
            }
            //RequestState::RequestWithBodyChunks(request_line, connection, host, Chunk::Ended) => { false }, */
            _ => unimplemented!(),
        }
    }

    pub fn next_slice_size<'a>(&self) -> usize {
        match *self {
            ResponseState::CopyingHeaders { ref header_slices, .. } => {
                header_slices.get(0).map(|h| match h {
                    CopyingSlice::Static(s) => s.len(),
                    CopyingSlice::Slice(s) => s.len(),
                }).unwrap_or(0)
            },
            ResponseState::Response{..} => 0,
            ResponseState::ResponseWithBody { length, .. } => {
                length
            }
            _ => unimplemented!(),
        }
    }

    pub fn needs_input(&self, buffer: usize) -> bool {
        unimplemented!()
    }

    // argument: how much was written
    // return: how much the buffer should be advanced
    //
    // if we're sending the headers, we do not want to advance
    // the buffer until all have been sent
    // also, if we are deleting a chunk of data, we might return a higher value
    pub fn consume(self, mut consumed: usize, buffer: &mut HttpBuffer) -> Self {
        let c = consumed;
        match self {
            ResponseState::CopyingHeaders { status, data,
                index, connection, upgrade,
                length, headers,
                mut header_slices } => {

                let mut v = Vec::new();

                let mut it = header_slices.drain(..);
                loop {
                    if let Some(h) = it.next() {
                        match h.consume(consumed) {
                            (remaining, None) => consumed = remaining,
                            (r, Some(slice)) => {
                                v.push(slice);
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }

                v.extend(it);
                header_slices = v;

                println!("response state consumed {} bytes, remaining slices: {:?}", c - consumed, header_slices);

                if !header_slices.is_empty() {
                    return ResponseState::CopyingHeaders { status, data, index,
                        connection,  upgrade, length, headers, header_slices };
                }

                println!("DATA SLICE WAS: {:?}", data.data(buffer.unparsed_data()));
                buffer.consume_parsed_data(index);
                println!("unparsed data: {}", buffer.unparsed_data().to_hex(16));
                let status_line = status.unwrap();

                let state = match upgrade {
                    Some(upgrade) => ResponseState::ResponseUpgrade { status: status_line, connection, upgrade },
                    None => match length {
                        None => ResponseState::Response { status: status_line, connection },
                        Some(LengthInformation::Length(sz)) => ResponseState::ResponseWithBody{ status: status_line, connection, length: sz},
                        Some(LengthInformation::Chunked) => ResponseState::ResponseWithBodyChunks{status: status_line, connection, chunk: Chunk::Initial},
                        //FIXME: missing body close delimited and response upgrade
                      }
                };

                println!("state is now {:?}", state);
                state
            },
            ResponseState::ResponseWithBody { status, connection,
                  length, .. } => {
                    buffer.consume_parsed_data(consumed);
                ResponseState::ResponseWithBody { status, connection, length: length - consumed }
            }
            _ => {
                println!("ResponseState::advance(): {:?}", &self);
                self
            },
        }
    }

    pub fn advance(self, buffer: &mut HttpBuffer) -> Self {
        match self {
            ResponseState::CopyingHeaders { status, data, index,
                connection, upgrade, length, headers, header_slices } => {
            
                if !header_slices.is_empty() {
                    return ResponseState::CopyingHeaders { status, data, index,
                        connection,  upgrade, length, headers, header_slices };
                }

                println!("DATA SLICE WAS: {:?}", data.data(buffer.unparsed_data()));
                buffer.consume_parsed_data(index);
                println!("unparsed data: {}", buffer.unparsed_data().to_hex(16));
                let status_line = status.unwrap();

                let state = match upgrade {
                    Some(upgrade) => ResponseState::ResponseUpgrade { status: status_line, connection, upgrade },
                    None => match length {
                        None => ResponseState::Response { status: status_line, connection },
                        Some(LengthInformation::Length(sz)) => ResponseState::ResponseWithBody{ status: status_line, connection, length: sz},
                        Some(LengthInformation::Chunked) => ResponseState::ResponseWithBodyChunks{status: status_line, connection, chunk: Chunk::Initial},
                        //FIXME: missing body close delimited and response upgrade
                      }
                };
                /*
                let state = match length {
                    None => RequestState::Request{ request: request_line, connection, host },
                    Some(LengthInformation::Length(length)) => RequestState::RequestWithBody{request: request_line, connection, host, length },
                    Some(LengthInformation::Chunked) => RequestState::RequestWithBodyChunks{request: request_line, connection, host, chunk: Chunk::Initial},
                };*/
                println!("state is now {:?}", state);
                state
            },
            _ => {
                println!("ResponseState::advance(): {:?}", &self);
                self
            },
        }
    }

    pub fn can_restart_parsing(&self, available_data: usize) -> bool {
        match self {
            ResponseState::Response{..} => true,
            ResponseState::ResponseWithBody { length: 0, ..} => true, 

            /*RequestState::RequestWithBody(request_line, connection, host, sz) => {
                false
            }*/
            //RequestState::RequestWithBodyChunks(request_line, connection, host, Chunk::Ended) => { false },
            s => {
                println!("called can_restart_parsing with {:?}", s);
                false
            },
        }
    }
}

pub fn default_response_result<O>(
    state: ResponseState,
    res: IResult<&[u8], O>,
) -> ResponseState {
    match res {
        Err(Err::Error(_)) | Err(Err::Failure(_)) => state.into_error(),
        Err(Err::Incomplete(_)) => state,
        _ => unreachable!(),
    }
}
/*
pub fn validate_response_header(
    mut state: ResponseState,
    header: &Header,
    is_head: bool,
) -> ResponseState {
    match header.value() {
        HeaderValue::ContentLength(sz) => {
            match state {
                // if the request has a HEAD method, we don't count the content length
                // FIXME: what happens if multiple content lengths appear?
                ResponseState::HasStatusLine { status, connection } => {
                    if is_head {
                        ResponseState::HasStatusLine { status, connection }
                    } else {
                        ResponseState::HasLength {
                            status,
                            connection,
                            length: LengthInformation::Length(sz),
                        }
                    }
                }
                s => s.into_error(),
            }
        }
        HeaderValue::Encoding(TransferEncodingValue::Chunked) => match state {
            ResponseState::HasStatusLine { status, connection } => {
                if is_head {
                    ResponseState::HasStatusLine { status, connection }
                } else {
                    ResponseState::HasLength {
                        status,
                        connection,
                        length: LengthInformation::Chunked,
                    }
                }
            }
            s => s.into_error(),
        },
        // FIXME: for now, we don't remember if we cancel indications from a previous Connection Header
        HeaderValue::Connection(c) => {
            if state
                .get_mut_connection()
                .map(|conn| {
                    if c.has_close {
                        conn.keep_alive = Some(false);
                    }
                    if c.has_keep_alive {
                        conn.keep_alive = Some(true);
                    }
                    if c.has_upgrade {
                        conn.has_upgrade = true;
                    }
                })
                .is_some()
            {
                if let ResponseState::HasUpgrade {
                    status,
                    connection,
                    upgrade,
                } = state
                {
                    if connection.has_upgrade {
                        ResponseState::HasUpgrade {
                            status,
                            connection,
                            upgrade,
                        }
                    } else {
                        ResponseState::Error {
                            status: Some(status),
                            connection: Some(connection),
                            upgrade: Some(upgrade),
                            length: None,
                            chunk: None,
                        }
                    }
                } else {
                    state
                }
            } else {
                state.into_error()
            }
        }
        HeaderValue::Upgrade(protocol) => {
            let proto = str::from_utf8(protocol)
                .expect("the parsed protocol should be a valid utf8 string")
                .to_string();
            trace!("parsed a protocol: {:?}", proto);
            trace!("state is {:?}", state);
            match state {
                ResponseState::HasStatusLine {
                    status,
                    mut connection,
                } => {
                    connection.upgrade = Some(proto.clone());
                    ResponseState::HasUpgrade {
                        status,
                        connection,
                        upgrade: proto,
                    }
                }
                s => s.into_error(),
            }
        }

        // FIXME: there should be an error for unsupported encoding
        HeaderValue::Encoding(_) => state,
        HeaderValue::Host(_) => state.into_error(),
        HeaderValue::Forwarded(_) => state.into_error(),
        HeaderValue::XForwardedFor(_) => state.into_error(),
        HeaderValue::XForwardedProto => state.into_error(),
        HeaderValue::XForwardedPort => state.into_error(),
        HeaderValue::Other(_, _) => state,
        HeaderValue::ExpectContinue => {
            // we should not get that one from the server
            state.into_error()
        }
        HeaderValue::Cookie(_) => state,
        HeaderValue::Error => state.into_error(),
    }
}

pub fn parse_response(
    state: ResponseState,
    buf: &[u8],
    is_head: bool,
    sticky_name: &str,
    app_id: Option<&str>,
) -> (BufferMove, ResponseState) {
    match state {
        ResponseState::Initial => {
            match status_line(buf) {
                Ok((i, r)) => {
                    if let Some(status) = RStatusLine::from_status_line(r) {
                        let connection = Connection::new();
                        /*let conn = if rl.version == "11" {
                          Connection::keep_alive()
                        } else {
                          Connection::close()
                        };
                        */
                        (
                            BufferMove::Advance(buf.offset(i)),
                            ResponseState::HasStatusLine { status, connection },
                        )
                    } else {
                        (
                            BufferMove::None,
                            ResponseState::Error {
                                status: None,
                                connection: None,
                                upgrade: None,
                                length: None,
                                chunk: None,
                            },
                        )
                    }
                }
                res => default_response_result(state, res),
            }
        }
        ResponseState::HasStatusLine { status, connection } => {
            match message_header(buf) {
                Ok((i, header)) => {
                    let mv = if header.should_delete(&connection, sticky_name) {
                        BufferMove::Delete(buf.offset(i))
                    } else {
                        BufferMove::Advance(buf.offset(i))
                    };
                    (
                        mv,
                        validate_response_header(
                            ResponseState::HasStatusLine { status, connection },
                            &header,
                            is_head,
                        ),
                    )
                }
                Err(Err::Incomplete(_)) => (
                    BufferMove::None,
                    ResponseState::HasStatusLine { status, connection },
                ),
                Err(_) => {
                    match crlf(buf) {
                        Ok((i, _)) => {
                            debug!("PARSER\theaders parsed, stopping");
                            // no content
                            if is_head ||
                // all 1xx responses
                status.status / 100  == 1 || status.status == 204 || status.status == 304
                            {
                                (
                                    BufferMove::Advance(buf.offset(i)),
                                    ResponseState::Response { status, connection },
                                )
                            } else {
                                // no length information, so we'll assume that the response ends when the connection is closed
                                (
                                    BufferMove::Advance(buf.offset(i)),
                                    ResponseState::ResponseWithBodyCloseDelimited {
                                        status,
                                        connection,
                                        back_closed: false,
                                    },
                                )
                            }
                        }
                        res => {
                            error!("PARSER\tHasStatusLine could not parse header for input(app={:?}):\n{}\n", app_id, buf.to_hex(16));
                            default_response_result(
                                ResponseState::HasStatusLine { status, connection },
                                res,
                            )
                        }
                    }
                }
            }
        }
        ResponseState::HasLength {
            status,
            connection,
            length,
        } => {
            match message_header(buf) {
                Ok((i, header)) => {
                    let mv = if header.should_delete(&connection, sticky_name) {
                        BufferMove::Delete(buf.offset(i))
                    } else {
                        BufferMove::Advance(buf.offset(i))
                    };
                    (
                        mv,
                        validate_response_header(
                            ResponseState::HasLength {
                                status,
                                connection,
                                length,
                            },
                            &header,
                            is_head,
                        ),
                    )
                }
                Err(Err::Incomplete(_)) => (
                    BufferMove::None,
                    ResponseState::HasLength {
                        status,
                        connection,
                        length,
                    },
                ),
                Err(_) => {
                    match crlf(buf) {
                        Ok((i, _)) => {
                            debug!("PARSER\theaders parsed, stopping");
                            match length {
                                LengthInformation::Chunked => (
                                    BufferMove::Advance(buf.offset(i)),
                                    ResponseState::ResponseWithBodyChunks {
                                        status,
                                        connection,
                                        chunk: Chunk::Initial,
                                    },
                                ),
                                LengthInformation::Length(sz) => (
                                    BufferMove::Advance(buf.offset(i)),
                                    ResponseState::ResponseWithBody {
                                        status,
                                        connection,
                                        length: sz,
                                    },
                                ),
                            }
                        }
                        res => {
                            error!("PARSER\tHasLength could not parse header for input(app={:?}):\n{}\n", app_id, buf.to_hex(16));
                            default_response_result(
                                ResponseState::HasLength {
                                    status,
                                    connection,
                                    length,
                                },
                                res,
                            )
                        }
                    }
                }
            }
        }
        ResponseState::HasUpgrade {
            status,
            connection,
            upgrade,
        } => {
            match message_header(buf) {
                Ok((i, header)) => {
                    let mv = if header.should_delete(&connection, sticky_name) {
                        BufferMove::Delete(buf.offset(i))
                    } else {
                        BufferMove::Advance(buf.offset(i))
                    };
                    (
                        mv,
                        validate_response_header(
                            ResponseState::HasUpgrade {
                                status,
                                connection,
                                upgrade,
                            },
                            &header,
                            is_head,
                        ),
                    )
                }
                Err(Err::Incomplete(_)) => (
                    BufferMove::None,
                    ResponseState::HasUpgrade {
                        status,
                        connection,
                        upgrade,
                    },
                ),
                Err(_) => {
                    match crlf(buf) {
                        Ok((i, _)) => {
                            debug!("PARSER\theaders parsed, stopping");
                            (
                                BufferMove::Advance(buf.offset(i)),
                                ResponseState::ResponseUpgrade {
                                    status,
                                    connection,
                                    upgrade,
                                },
                            )
                        }
                        res => {
                            error!("PARSER\tHasUpgrade could not parse header for input(app={:?}):\n{}\n", app_id, buf.to_hex(16));
                            default_response_result(
                                ResponseState::HasUpgrade {
                                    status,
                                    connection,
                                    upgrade,
                                },
                                res,
                            )
                        }
                    }
                }
            }
        }
        ResponseState::ResponseWithBodyChunks {
            status,
            connection,
            chunk,
        } => {
            let (advance, chunk) = chunk.parse(buf);
            (
                advance,
                ResponseState::ResponseWithBodyChunks {
                    status,
                    connection,
                    chunk,
                },
            )
        }
        ResponseState::ResponseWithBodyCloseDelimited {
            status,
            connection,
            back_closed,
        } => (
            BufferMove::Advance(buf.len()),
            ResponseState::ResponseWithBodyCloseDelimited {
                status,
                connection,
                back_closed,
            },
        ),
        _ => {
            error!("PARSER\tunimplemented state: {:?}", state);
            (BufferMove::None, state.into_error())
        }
    }
}
*/

pub fn parse_response_until_stop(
    mut state: ResponseState,
    mut header_end: Option<usize>,
    buffer: &mut HttpBuffer,
    is_head: bool,
    added_res_header: &str,
    sticky_name: &str,
    sticky_session: Option<&StickySession>,
    app_id: Option<&str>,
) -> (ResponseState, Option<usize>) {
    let buf = buffer.unparsed_data();
    info!("will parse:\n{}", buf.to_hex(16));

    loop {
        info!("state: {:?}", state);
        match state {
            ResponseState::Initial => match header::status_line(buf) {
                Ok((i, (version, status, reason))) => {
                    let sline = StatusLine::new(buf, version, status, reason);
                    println!("sline: {:?}", sline);
                    state = ResponseState::Parsing {
                        status: sline,
                        headers: Vec::new(),
                        index: buf.offset(i),
                    };
                }
                Err(Err::Incomplete(_)) => break,
                res => {
                    println!("err: {:?}", res);
                    state = default_response_result(state, res);
                    break;
                }
            },
            ResponseState::Parsing {
                status,
                mut headers,
                index,
            } => {
                //println!("will parse header:\n{}", &buf[index..].to_hex(16));
                match message_header(&buf[index..]) {
                    Ok((i, header)) => {
                        println!("header: {:?}", header);
                        headers.push(Header::new(buf, header.name, header.value));
                        state = ResponseState::Parsing {
                            status,
                            headers,
                            index: buf.offset(i),
                        };
                    }
                    Err(_) => match crlf(&buf[index..]) {
                        Ok((i, o)) => {
                            
                            state = ResponseState::ParsingDone {
                                status,
                                headers,
                                index: buf.offset(i),
                                data: Slice::new(buf, i, Meta::Data),
                            };
                            println!("parsing done from\n{}\nremaining ->\n{}\nstate: {:?}",
                            (&buf[index..]).to_hex(16), i.to_hex(16), state);
                            break;
                        }
                        res => {
                            state = default_response_result(
                                ResponseState::Parsing {
                                    status,
                                    headers,
                                    index,
                                },
                                res,
                            );
                            break;
                        }
                    },
                    res => {
                        state = default_response_result(
                            ResponseState::Parsing {
                                status,
                                headers,
                                index,
                            },
                            res,
                        );
                        break;
                    }
                }
            }
            s => panic!(
                "parse_response_until_stop should not be called with this state: {:?}",
                s
            ),
        }
    }

    let header_end = if let ResponseState::ParsingDone { index, .. } = state {
        Some(index)
    } else {
        None
    };

    state = match state {
        ResponseState::ParsingDone {
            status,
            headers,
            index,
            data,
        } => finish_response(
            status,
            headers,
            index,
            data,
            buffer,
            added_res_header,
            sticky_name,
        ),
        s => s,
    };

    (state, header_end)
    /*
    loop {
        //trace!("PARSER\t{}\tpos[{}]: {:?}", request_id, position, current_state);
        let (mv, new_state) = parse_response(
            current_state,
            buf.unparsed_data(),
            is_head,
            sticky_name,
            app_id,
        );
        //trace!("PARSER\tinput:\n{}\nmv: {:?}, new state: {:?}\n", buf.unparsed_data().to_hex(16), mv, new_state);
        //trace!("PARSER\t{}\tmv: {:?}, new state: {:?}\n", request_id, mv, new_state);
        current_state = new_state;

        match mv {
            BufferMove::Advance(sz) => {
                assert!(sz != 0, "buffer move should not be 0");

                // header_end is some if we already parsed the headers
                if header_end.is_none() {
                    match current_state {
                        ResponseState::Response { .. }
                        | ResponseState::ResponseUpgrade { .. }
                        | ResponseState::ResponseWithBodyChunks { .. } => {
                            buf.insert_output(Vec::from(added_res_header.as_bytes()));
                            add_sticky_session_to_response(buf, sticky_name, sticky_session);

                            buf.consume_parsed_data(sz);
                            header_end = Some(buf.start_parsing_position);

                            buf.slice_output(sz);
                        }
                        ResponseState::ResponseWithBody { length, .. } => {
                            buf.insert_output(Vec::from(added_res_header.as_bytes()));
                            add_sticky_session_to_response(buf, sticky_name, sticky_session);

                            buf.consume_parsed_data(sz);
                            header_end = Some(buf.start_parsing_position);

                            buf.slice_output(sz + length);
                            buf.consume_parsed_data(length);
                        }
                        ResponseState::ResponseWithBodyCloseDelimited {
                            ref connection, ..
                        } => {
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
                        }
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
            }
            BufferMove::Delete(length) => {
                buf.consume_parsed_data(length);
                if header_end.is_none() {
                    match current_state {
                        ResponseState::Response { .. }
                        | ResponseState::ResponseUpgrade { .. }
                        | ResponseState::ResponseWithBodyChunks { .. } => {
                            //println!("FOUND HEADER END (delete):{}", buf.start_parsing_position);
                            header_end = Some(buf.start_parsing_position);
                            buf.insert_output(Vec::from(added_res_header.as_bytes()));
                            add_sticky_session_to_response(buf, sticky_name, sticky_session);

                            buf.delete_output(length);
                        }
                        ResponseState::ResponseWithBody { length, .. } => {
                            header_end = Some(buf.start_parsing_position);
                            buf.insert_output(Vec::from(added_res_header.as_bytes()));
                            buf.delete_output(length);

                            add_sticky_session_to_response(buf, sticky_name, sticky_session);

                            buf.slice_output(length);
                            buf.consume_parsed_data(length);
                        }
                        _ => {
                            buf.delete_output(length);
                        }
                    }
                } else {
                    buf.delete_output(length);
                }
            }
            _ => break,
        }

        match current_state {
            ResponseState::Error { .. } => {
                incr!("http1.parser.response.error");
                break;
            }
            ResponseState::Response { .. }
            | ResponseState::ResponseWithBody { .. }
            | ResponseState::ResponseUpgrade { .. }
            | ResponseState::ResponseWithBodyChunks {
                chunk: Chunk::Ended,
                ..
            }
            | ResponseState::ResponseWithBodyCloseDelimited { .. } => break,
            _ => (),
        }
        //println!("move: {:?}, new state: {:?}, input_queue {:?}, output_queue: {:?}", mv, current_state, buf.input_queue, buf.output_queue);
    }

    //println!("end state: {:?}, input_queue {:?}, output_queue: {:?}", current_state, buf.input_queue, buf.output_queue);
    (current_state, header_end)
    */
}

fn add_sticky_session_to_response(
    buf: &mut BufferQueue,
    sticky_name: &str,
    sticky_session: Option<&StickySession>,
) {
    if let Some(ref sticky_backend) = sticky_session {
        let sticky_cookie = format!(
            "Set-Cookie: {}={}; Path=/\r\n",
            sticky_name, sticky_backend.sticky_id
        );
        buf.insert_output(Vec::from(sticky_cookie.as_bytes()));
    }
}

fn finish_response(
 status: StatusLine,
    mut headers: Vec<Header>,
    index: usize,
    data: Slice,
    buffer: &mut HttpBuffer,
    added_res_header: &str,
    sticky_name: &str,
) -> ResponseState {
    let mut connection = Connection::new();
    let mut length: Option<LengthInformation> = None;
    let mut upgrade: Option<UpgradeProtocol> = None;
    let status_line = status.to_rstatus_line(buffer.unparsed_data());

    for header in headers.iter() {
        match header.name.meta {
            Meta::HeaderName(HeaderName::ContentLength) => {
                match header.value.data(buffer.unparsed_data()) {
                    None => unimplemented!(),
                    Some(s) => match str::from_utf8(s).ok().and_then(|s| s.parse::<usize>().ok()) {
                        None => unimplemented!(),
                        Some(sz) => {
                            if length.is_none() {
                                length = Some(LengthInformation::Length(sz));
                                // we should allow multiple Content-Length headers if they have the same value
                            } else {
                                return ResponseState::Error {
                                    status: Some(status),
                                    headers,
                                    data: Some(data),
                                    index,
                                    upgrade: None,
                                    connection: Some(connection),
                                    length,
                                    chunk: None,
                                };
                            }
                        }
                    },
                }
            }
            Meta::HeaderName(HeaderName::TransferEncoding) => {
                match header.value.data(buffer.unparsed_data()) {
                    None => unimplemented!(),
                    Some(s) => {
                        for value in super::comma_separated_values(s) {
                            // Transfer-Encoding gets the priority over Content-Length
                            if super::compare_no_case(value, b"chunked") {
                                length = Some(LengthInformation::Chunked);
                            }
                        }
                    }
                }
            }

            Meta::HeaderName(HeaderName::Connection) => {
                match header.value.data(buffer.unparsed_data()) {
                    None => unimplemented!(),
                    Some(s) => {
                        for value in super::comma_separated_values(s) {
                            println!(
                                "connection header contains: {:?}",
                                std::str::from_utf8(value)
                            );
                            if super::compare_no_case(value, b"close") {
                                connection.keep_alive = Some(false);
                                continue;
                            }
                            if super::compare_no_case(value, b"keep-alive") {
                                connection.keep_alive = Some(true);
                                continue;
                            }
                            /*if super::compare_no_case(value, b"upgrade") {
                                connection.has_upgrade = true;
                                continue;
                            }*/
                        }
                    }
                }
            }

            /*
            
            
            Meta::HeaderName(HeaderName::Expect) => match header.value.data(buffer.unparsed_data())
            {
                None => unimplemented!(),
                Some(s) => {
                    if super::compare_no_case(s, b"100-continue") {
                        connection.continues = Continue::Expects(0);
                    }
                }
            },
            Meta::HeaderName(HeaderName::Forwarded) => {
                match header.value.data(buffer.unparsed_data()) {
                    None => unimplemented!(),
                    Some(s) => {
                        connection.forwarded.forwarded = String::from_utf8(s.to_vec()).ok();
                    }
                }
            }
            Meta::HeaderName(HeaderName::XForwardedFor) => {
                match header.value.data(buffer.unparsed_data()) {
                    None => unimplemented!(),
                    Some(s) => {
                        connection.forwarded.x_for = String::from_utf8(s.to_vec()).ok();
                    }
                }
            }
            Meta::HeaderName(HeaderName::XForwardedPort) => connection.forwarded.x_port = true,
            Meta::HeaderName(HeaderName::XForwardedProto) => connection.forwarded.x_proto = true,
            Meta::HeaderName(HeaderName::Upgrade) => {
                match header.value.data(buffer.unparsed_data()) {
                    None => unimplemented!(),
                    Some(s) => {
                        connection.upgrade = String::from_utf8(s.to_vec()).ok();
                    }s
                }
            }
            Meta::HeaderName(HeaderName::Cookie) => match header.value.data(buffer.unparsed_data())
            {
                None => unimplemented!(),
                Some(s) => match parse_request_cookies(s) {
                    None => {
                        return RequestState::Error {
                            request: Some(request),quest
                            headers,
                            data: Some(data),
                            index,
                            host,
                            connection: Some(connection),
                            length,
                            chunk: None,
                        }
                    }
                    Some(cookies) => {
                        let sticky_session_header = cookies
                            .into_iter()
                            .find(|cookie| &(cookie.name)[..] == sticky_name.as_bytes());
                        if let Some(sticky_session) = sticky_session_header {
                            connection.sticky_session = str::from_utf8(sticky_session.value)
                                .map(|s| s.to_string())
                                .ok();
                        }
                    }
                },
            },*/
            _ => {}
        };
    }

    let upgrade : Option<String>  = None;

    if status_line.is_none() {
        unimplemented!();
    }
    let status_line = status_line.unwrap();

    /*
    let state = match upgrade {
        Some(upgrade) => ResponseState::ResponseUpgrade { status: status_line, connection, upgrade },
        None => match length {
            None => ResponseState::Response { status: status_line, connection },
            Some(LengthInformation::Length(sz)) => ResponseState::ResponseWithBody{ status: status_line, connection, length: sz},
            Some(LengthInformation::Chunked) => ResponseState::ResponseWithBodyChunks{status: status_line, connection, chunk: Chunk::Initial},
            //FIXME: missing body close delimited and response upgrade
          }
    };

       Response {
        status: RStatusLine,
        connection: Connection,
    },
    ResponseUpgrade {
        status: RStatusLine,
        connection: Connection,
        upgrade: UpgradeProtocol,
    },
    ResponseWithBody {
        status: RStatusLine,
        connection: Connection,
        length: usize,
    },
    ResponseWithBodyChunks {
        status: RStatusLine,
        connection: Connection,
        chunk: Chunk,
    },
    // the boolean indicates if the backend connection is closed
    ResponseWithBodyCloseDelimited {
        status: RStatusLine,
        connection: Connection,
        back_closed: bool,
    },
     */

    let mut header_slices = Vec::new();
    status.as_copying_slices(&mut header_slices);
    for h in headers.iter() {
        h.as_copying_slices(&mut header_slices);
    }

    header_slices.push(CopyingSlice::Static(&b"\r\n"[..]));

    let state = ResponseState::CopyingHeaders {
        status: Some(status_line),
        headers,
        data,
        index,
        connection,
        upgrade,
        length,
        header_slices,
    };

    println!("result state: {:?}", state);
    state
}