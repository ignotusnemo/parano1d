use std::borrow::Cow;
use std::io::{Read, Write};

const COMPRESSED: u8 = 0xff;
const PREFIX: usize = 5;
const WINDOW_LOG_MAX: u32 = 23;

pub(super) fn pack(payload: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    if payload.is_empty() || payload.first() == Some(&COMPRESSED) {
        return Err(());
    }
    let length = u32::try_from(payload.len()).map_err(|_| ())?;
    let mut output = vec![COMPRESSED];
    output.extend_from_slice(&length.to_le_bytes());
    let mut encoder = zstd::stream::write::Encoder::new(output, 3).map_err(|_| ())?;
    encoder.include_checksum(true).map_err(|_| ())?;
    encoder.write_all(payload).map_err(|_| ())?;
    let output = encoder.finish().map_err(|_| ())?;
    Ok((output.len() < payload.len()).then_some(output))
}

pub(super) fn unpack(payload: &[u8], maximum: usize) -> Result<Cow<'_, [u8]>, ()> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(());
    }
    if payload.first() != Some(&COMPRESSED) {
        return Ok(Cow::Borrowed(payload));
    }
    let length = u32::from_le_bytes(
        payload
            .get(1..PREFIX)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    ) as usize;
    if length == 0 || length > maximum {
        return Err(());
    }
    let frame = payload.get(PREFIX..).ok_or(())?;
    let mut decoder = zstd::stream::read::Decoder::with_buffer(frame)
        .map_err(|_| ())?
        .single_frame();
    decoder.window_log_max(WINDOW_LOG_MAX).map_err(|_| ())?;
    let mut output = Vec::with_capacity(length);
    decoder
        .by_ref()
        .take(length as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|_| ())?;
    if output.len() != length || !decoder.finish().is_empty() {
        return Err(());
    }
    Ok(Cow::Owned(output))
}
