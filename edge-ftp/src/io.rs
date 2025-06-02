use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use edge_nal::{io::{Read, Write}, TcpConnect};

pub enum FtpError<T: TcpConnect> {
    TcpErr(T::Error),
    InvalidResponse,
    Utf8Error,
    CodeParseError,
    UnexpectedResponse(u32),
    BufferError,
    PasswordRequired
}

pub enum FtpCommand<'b> {
    User(&'b str),
    Pass(&'b str),
    Retr(&'b str),
    Pasv
}

impl<'a> FtpCommand<'a> {
    pub fn write_to_buf<T: TcpConnect>(&self, buf: &mut [u8]) -> Result<usize, FtpError<T>> {
        match self {
            FtpCommand::User(s) => Self::write_with_prefix(b"USER ", Some(s), buf),
            FtpCommand::Pass(s) => Self::write_with_prefix(b"PASS ", Some(s), buf),
            FtpCommand::Retr(s) => Self::write_with_prefix(b"RETR ", Some(s), buf),
            FtpCommand::Pasv => Self::write_with_prefix(b"PASV", None, buf)
        }
    }
    fn write_with_prefix<T: TcpConnect>(prefix: &[u8], data: Option<&str>, buf: &mut [u8]) -> Result<usize, FtpError<T>> {
        buf[..prefix.len()].copy_from_slice(prefix);
        let mut total_len = prefix.len();
        if let Some(data) = data {
            let data_bytes = data.as_bytes();
            total_len += data_bytes.len();

            if buf.len() < total_len {
                return Err(FtpError::BufferError);
            }

            buf[prefix.len()..total_len].copy_from_slice(data_bytes);
        }
        if buf.len() < total_len + 2 {
            return Err(FtpError::BufferError);
        }
    
        buf[total_len] = b'\r';
        buf[total_len + 1] = b'\n';
        total_len += 2;
        Ok(total_len)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum FtpStatus {
    AlreadyOpen = 125,
    AboutToSend = 150,
    Ready = 220,
    System = 211,
    ClosingDataConnection = 226,
    PassiveMode = 227,
    LoggedIn = 230,
    RequestedFileActionOk = 250,
    NeedPassword = 331,
    Unknown = 0
}

impl From<u32> for FtpStatus {
    fn from(code: u32) -> Self {
        match code {
            125 => Self::AlreadyOpen,
            150 => Self::AboutToSend,
            220 => Self::Ready,
            211 => Self::System,
            226 => Self::ClosingDataConnection,
            227 => Self::PassiveMode,
            230 => Self::LoggedIn,
            250 => Self::RequestedFileActionOk,
            331 => Self::NeedPassword,
            _ => Self::Unknown
        }
    }
}

pub struct FtpResponse {
    pub status: FtpStatus,
    pub len: usize,
}


pub struct FtpClient<'a, T: TcpConnect> {
    stack: &'a T,
    io: T::Socket<'a>,
    buf: &'a mut [u8]
}

impl<'a, T: TcpConnect> FtpClient<'a, T> {
    pub async fn new(stack: &'a T, buf: &'a mut [u8], addr: SocketAddr, user: Option<&'a str>, password: Option<&'a str>) -> Result<Self, FtpError<T>> {
        let io = stack.connect(addr).await.map_err(FtpError::<T>::TcpErr)?;
        let mut ftp = Self { stack, io, buf };
        ftp.read_response(FtpStatus::Ready).await?;
        if let Some(user) = user {
            ftp.perform(FtpCommand::User(user)).await?;
            let response = ftp.read_response_in(&[FtpStatus::LoggedIn, FtpStatus::NeedPassword])
            .await?;
            if response.status == FtpStatus::NeedPassword {
                if let Some(password) = password {
                    ftp.perform(FtpCommand::Pass(password)).await?;
                    ftp.read_response(FtpStatus::LoggedIn).await?;
                } else {
                    return Err(FtpError::PasswordRequired);
                }
            }
        }
        Ok(ftp)
    }

    pub async fn retrv<'b>(&mut self, file_name: &'a str, buf: &'b mut [u8]) -> Result<&'b [u8], FtpError<T>> {
        self.retr_file(file_name, |mut stream|  {
            async move {
                let mut total = 0;
                while total < buf.len() {
                    let n = stream.read(&mut buf[total..]).await.map_err(FtpError::<T>::TcpErr)?;
                    if n == 0 {
                        return Ok(&buf[..total]);
                    }
                    total += n;
                }
                let mut probe = [0u8; 1];
                let more = stream.read(&mut probe).await.map_err(FtpError::<T>::TcpErr)?;
                if more > 0 {
                    return Err(FtpError::BufferError);
                }
                Ok(&buf[..total])
            }
        }).await
    }

    async fn retr_file<F, P, D>(&mut self, file_name: &'a str, reader: F) -> Result<D, FtpError<T>>
    where 
        F: FnOnce(T::Socket<'a>) -> P,
        P: core::future::Future<Output = Result<D, FtpError<T>>>
    {
        let stream = self.data_command(FtpCommand::Retr(file_name)).await?;
        self.read_response_in(&[FtpStatus::AboutToSend, FtpStatus::AlreadyOpen]).await?;
        let res = reader(stream).await?;
        self.read_response_in(&[FtpStatus::ClosingDataConnection, FtpStatus::RequestedFileActionOk]).await?;
        Ok(res)
    }

    async fn data_command(&mut self, command: FtpCommand<'a>) -> Result<T::Socket<'a>, FtpError<T>> {
        let addr = self.pasv().await?;
        self.perform(command).await?;
        let io = self.stack.connect(addr).await.map_err(FtpError::<T>::TcpErr)?;
        Ok(io)
    }

    async fn pasv(&mut self) -> Result<SocketAddr, FtpError<T>> {
        self.perform(FtpCommand::Pasv).await?;
        let response = self.read_response(FtpStatus::PassiveMode).await?;
        Self::parse_pasv_response(&self.buf[0..response.len]).map_err(|_| FtpError::InvalidResponse)
    }

    async fn perform(&mut self, command: FtpCommand<'a>) -> Result<(), FtpError<T>> {
        let len = command.write_to_buf(self.buf)?;

        self.io
            .write_all(&self.buf[0..len])
            .await
            .map_err(FtpError::<T>::TcpErr)
    }

    async fn read_response(&mut self, expected_code: FtpStatus) -> Result<FtpResponse, FtpError<T>> {
        self.read_response_in(&[expected_code]).await
    }

    async fn read_response_in(&mut self, expected_code: &[FtpStatus]) -> Result<FtpResponse, FtpError<T>> {
        let mut offset = 0;
        let mut len = self.read_until_new_line(offset).await?;

        offset += len;

        if offset < 5 {
            return Err(FtpError::InvalidResponse);
        }
        
        let code_word = Self::code_from_buffer(&self.buf[0..len], 3)?;
        let code = FtpStatus::from(code_word);

        let expected = [self.buf[0], self.buf[1], self.buf[2], 0x20];
        let alt_expected = if expected_code.contains(&FtpStatus::System) {
            [self.buf[0], self.buf[1], self.buf[2], b'-']
        } else {
            expected
        };

        while len < 5 || ((&self.buf[offset - len..offset])[0..4] != expected && (&self.buf[offset - len..offset])[0..4] != alt_expected) {
            len = self.read_until_new_line(offset).await?;
            offset += len;
        }

        if expected_code.iter().any(|ec| code == *ec) {
            Ok(FtpResponse { status: code, len: offset })
        } else {
            Err(FtpError::UnexpectedResponse(code_word))
        }
    }
    async fn read_until_new_line(&mut self, offset: usize) -> Result<usize, FtpError<T>> {
        let mut found = false;
        let mut len = 0;
        while offset + len < self.buf.len() {
            let x = self.io.read(&mut self.buf[offset..offset + 1]).await.map_err(FtpError::TcpErr)?;
            if x == 0 {
                break;
            }
            assert!(x == 1);
            len += 1;
            if self.buf[offset + len - 1] == 0x0A {
                found = true;
                break;
            }
        }
        if found {
            return Ok(len);
        }
        if offset + len == self.buf.len() {
            return Err(FtpError::BufferError);
        }
        return Err(FtpError::InvalidResponse)
    }

    fn code_from_buffer(buf: &[u8], len: usize) -> Result<u32, FtpError<T>> {
        if buf.len() < len {
            return Err(FtpError::InvalidResponse);
        }
        let buffer = &buf[0..len];
        let as_string = str::from_utf8(buffer).map_err(|_| FtpError::InvalidResponse)?;
        as_string.parse::<u32>().map_err(|_| FtpError::InvalidResponse)
    }
    fn parse_pasv_response(buf: &[u8]) -> Result<SocketAddr, ()> {
        let mut start = None;
    
        for (i, &b) in buf.iter().enumerate() {
            if b == b'(' {
                start = Some(i + 1);
                break;
            }
        }
    
        let start = start.ok_or(())?;
    
        let mut end = None;
        for (i, &b) in buf[start..].iter().enumerate() {
            if b == b')' {
                end = Some(start + i);
                break;
            }
        }
    
        let end = end.ok_or(())?;
    
        let inner = &buf[start..end]; 
    
        let mut parts = [0u8; 6];
        let mut idx = 0;
        let mut val: u16 = 0;
    
        for &b in inner {
            match b {
                b'0'..=b'9' => {
                    val = val.checked_mul(10).and_then(|v| v.checked_add((b - b'0') as u16)).ok_or(())?;
                }
                b',' => {
                    if idx >= 6 {
                        return Err(());
                    }
                    parts[idx] = val as u8;
                    idx += 1;
                    val = 0;
                }
                _ => return Err(()),
            }
        }
    
        if idx != 5 {
            return Err(());
        }
    
        parts[5] = val as u8;

        let ip = Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]);

        let port = (u16::from(parts[4]) << 8 ) | u16::from(parts[5]);
        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}
