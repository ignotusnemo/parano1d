use super::*;
use crate::acceptance::history_step::v2::{capacity_banked as bank, V2Config, V2Error};

const MAGIC: &[u8; 8] = b"O1V21K01";
const PROOF_HASH_MAGIC: &[u8; 8] = b"O1V5K001";

fn flags(config: bank::Config) -> u64 {
    u64::from(config.fused_pins())
        | (u64::from(config.reuses_linear_rows()) << 1)
        | (u64::from(config.shared_m24()) << 2)
        | (u64::from(config.product_aliases()) << 3)
}

fn config_with_flags(configs: [V2Config; 3], flags: u64) -> Result<bank::Config, V2Error> {
    if flags & !15 != 0 {
        return Err(encoding().into());
    }
    let mut config = bank::Config::new(configs[0], configs[1], configs[2])?;
    if flags & 1 != 0 {
        config = config.with_fused_pins();
    }
    if flags & 2 != 0 {
        config = config.with_reused_linear_rows();
    }
    if flags & 4 != 0 {
        config = config.with_shared_m24();
    }
    if flags & 8 != 0 {
        config = config.with_product_aliases();
    }
    Ok(config)
}

fn validate_slices(
    slices: SelectedZkBlockRegionVkSlices,
    m: usize,
) -> Result<(), HistoryStepError> {
    for slice in slices
        .wallet_a
        .into_iter()
        .chain(slices.meta_a)
        .chain(slices.wallet_b)
        .chain(slices.meta_b)
        .chain(slices.owner_c)
        .chain(slices.main_c)
    {
        if slice.log2_len > m || slice.index >= (1usize << (m - slice.log2_len)) {
            return Err(encoding());
        }
    }
    Ok(())
}

impl bank::RuntimeParts {
    pub fn encode_compact(&self) -> Result<Vec<u8>, V2Error> {
        if !self.config().is_active(bank::Class::Large) {
            return encode_proof_hash(self);
        }
        let configs = bank::Class::ALL.map(|class| {
            let mut bytes = Vec::new();
            put_explicit_v2_config(&mut bytes, self.config().class(class));
            bytes
        });
        let mut expected = 24usize;
        for class in bank::Class::ALL {
            expected = checked_add(expected, configs[class.index()].len())?;
            expected = checked_add(expected, BLOCK_SLICE_COUNT * SLICE_BYTES)?;
            expected = checked_add(expected, layout_len(self.child_layout(class))?)?;
            expected = checked_add(expected, layout_len(self.parent_layout(class))?)?;
            validate_slices(
                self.block_vk(class).selected_registry_slices()?,
                self.config().class(class).outer_m(),
            )?;
        }
        if expected > HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES {
            return Err(encoding().into());
        }
        let mut out = Vec::with_capacity(expected);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(noid_tx::experimental_object::OBJECT_VERSION as u64).to_le_bytes());
        out.extend_from_slice(&flags(self.config()).to_le_bytes());
        for class in bank::Class::ALL {
            out.extend_from_slice(&configs[class.index()]);
            put_block_slices(&mut out, self.block_vk(class).selected_registry_slices()?)?;
            put_layout(&mut out, self.child_layout(class))?;
            put_layout(&mut out, self.parent_layout(class))?;
        }
        if out.len() != expected {
            return Err(encoding().into());
        }
        Ok(out)
    }

    pub fn decode_compact(encoded: &[u8]) -> Result<Self, V2Error> {
        if encoded.starts_with(PROOF_HASH_MAGIC) {
            return decode_proof_hash(encoded);
        }
        let mut preflight = Reader::new(encoded)?;
        if preflight.take(8)? != MAGIC
            || preflight.take(8)?
                != (noid_tx::experimental_object::OBJECT_VERSION as u64).to_le_bytes()
        {
            return Err(encoding().into());
        }
        let flags = u64::from_le_bytes(preflight.take(8)?.try_into().map_err(|_| encoding())?);
        if flags & !15 != 0 {
            return Err(encoding().into());
        }
        let mut configs = Vec::with_capacity(3);
        for _ in 0..3 {
            let config = read_explicit_v2_config(&mut preflight)?;
            validate_slices(read_block_slices(&mut preflight)?, config.outer_m())?;
            preflight_layout(&mut preflight)?;
            preflight_layout(&mut preflight)?;
            configs.push(config);
        }
        preflight.finish()?;
        let configs: [V2Config; 3] = configs.try_into().map_err(|_| encoding())?;
        let config = config_with_flags(configs, flags)?;
        if !config.is_active(bank::Class::Large) {
            return Err(encoding().into());
        }
        let mut reader = Reader::new(encoded)?;
        reader.take(24)?;
        let mut blocks = Vec::with_capacity(3);
        let mut children = Vec::with_capacity(3);
        let mut parents = Vec::with_capacity(3);
        for expected in configs {
            let decoded = read_explicit_v2_config(&mut reader)?;
            if decoded != expected {
                return Err(encoding().into());
            }
            blocks.push(BlockRegionSidecarVk::from_object_registry_slices(
                decoded.block_geometry(),
                read_block_slices(&mut reader)?,
            )?);
            children.push(read_layout(&mut reader)?);
            parents.push(read_layout(&mut reader)?);
        }
        reader.finish()?;
        let parts = Self::new(
            config,
            blocks.try_into().map_err(|_| encoding())?,
            children.try_into().map_err(|_| encoding())?,
            parents.try_into().map_err(|_| encoding())?,
        )?;
        if parts.encode_compact()? != encoded {
            return Err(encoding().into());
        }
        Ok(parts)
    }
}

fn encode_proof_hash(parts: &bank::RuntimeParts) -> Result<Vec<u8>, V2Error> {
    let config = parts.config();
    let mut out = Vec::new();
    out.extend_from_slice(PROOF_HASH_MAGIC);
    out.extend_from_slice(&(noid_tx::experimental_object::OBJECT_VERSION as u64).to_le_bytes());
    out.extend_from_slice(&flags(config).to_le_bytes());
    // Retain the predecessor capacities as transition metadata. Only the two
    // active classes have a block key or a recursive transcript in this bank.
    for class in bank::Class::ALL {
        put_explicit_v2_config(&mut out, config.class(class));
    }
    for &class in config.active_classes() {
        validate_slices(
            parts.block_vk(class).selected_registry_slices()?,
            config.class(class).outer_m(),
        )?;
        put_block_slices(&mut out, parts.block_vk(class).selected_registry_slices()?)?;
        put_layout(&mut out, parts.child_layout(class))?;
        put_layout(&mut out, parts.parent_layout(class))?;
        if out.len() > HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES {
            return Err(encoding().into());
        }
    }
    Ok(out)
}

fn proof_hash_header(reader: &mut Reader<'_>) -> Result<bank::Config, V2Error> {
    if reader.take(8)? != PROOF_HASH_MAGIC
        || reader.take(8)? != (noid_tx::experimental_object::OBJECT_VERSION as u64).to_le_bytes()
    {
        return Err(encoding().into());
    }
    let flags = u64::from_le_bytes(reader.take(8)?.try_into().map_err(|_| encoding())?);
    let configs = [
        read_explicit_v2_config(reader)?,
        read_explicit_v2_config(reader)?,
        read_explicit_v2_config(reader)?,
    ];
    let config = config_with_flags(configs, flags)?;
    if config.is_active(bank::Class::Large) {
        return Err(encoding().into());
    }
    Ok(config)
}

fn decode_proof_hash(encoded: &[u8]) -> Result<bank::RuntimeParts, V2Error> {
    let mut preflight = Reader::new(encoded)?;
    let config = proof_hash_header(&mut preflight)?;
    for &class in config.active_classes() {
        validate_slices(
            read_block_slices(&mut preflight)?,
            config.class(class).outer_m(),
        )?;
        preflight_layout(&mut preflight)?;
        preflight_layout(&mut preflight)?;
    }
    preflight.finish()?;
    let mut reader = Reader::new(encoded)?;
    if proof_hash_header(&mut reader)? != config {
        return Err(encoding().into());
    }
    let mut blocks = Vec::new();
    let mut children = Vec::new();
    let mut parents = Vec::new();
    for &class in config.active_classes() {
        blocks.push(BlockRegionSidecarVk::from_object_registry_slices(
            config.class(class).block_geometry(),
            read_block_slices(&mut reader)?,
        )?);
        children.push(read_layout(&mut reader)?);
        parents.push(read_layout(&mut reader)?);
    }
    reader.finish()?;
    let parts = bank::RuntimeParts::new(
        config,
        [blocks[0].clone(), blocks[0].clone(), blocks[1].clone()],
        [
            children[0].clone(),
            children[0].clone(),
            children[1].clone(),
        ],
        [parents[0].clone(), parents[0].clone(), parents[1].clone()],
    )?;
    if parts.encode_compact()? != encoded {
        return Err(encoding().into());
    }
    Ok(parts)
}
