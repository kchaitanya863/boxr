use super::store::NetworkEndpoint;
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Open/Closed: IP allocation strategy
pub trait IpAllocator: Send + Sync {
    fn allocate(
        &self,
        subnet_str: &str,
        gateway_str: &str,
        existing: &HashMap<String, NetworkEndpoint>,
    ) -> Result<Ipv4Addr>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SubnetIpAllocator;

impl IpAllocator for SubnetIpAllocator {
    fn allocate(
        &self,
        subnet_str: &str,
        gateway_str: &str,
        existing: &HashMap<String, NetworkEndpoint>,
    ) -> Result<Ipv4Addr> {
        allocate_ip_in_subnet(subnet_str, gateway_str, existing)
    }
}

pub fn parse_cidr_range(subnet_str: &str) -> Result<(u32, u32)> {
    let (ip_part, mask_part) = subnet_str
        .split_once('/')
        .ok_or_else(|| anyhow!("Invalid CIDR subnet {}", subnet_str))?;

    let base_ip: Ipv4Addr = ip_part.parse()?;
    let prefix_len: u32 = mask_part.parse().context("Invalid CIDR prefix length")?;

    if prefix_len > 32 {
        return Err(anyhow!("Unsupported subnet prefix length /{}", prefix_len));
    }

    let mask_u32 = if prefix_len == 0 {
        0
    } else {
        (!0u32) << (32 - prefix_len)
    };
    let base_u32 = u32::from(base_ip) & mask_u32;
    let bcast_u32 = base_u32 | (!mask_u32);
    Ok((base_u32, bcast_u32))
}

pub fn subnets_overlap(sub1: &str, sub2: &str) -> Result<bool> {
    if sub1.contains(':') || sub2.contains(':') {
        return Ok(sub1.trim() == sub2.trim());
    }
    let (start1, end1) = parse_cidr_range(sub1)?;
    let (start2, end2) = parse_cidr_range(sub2)?;
    Ok(start1 <= end2 && start2 <= end1)
}

pub fn allocate_ip_in_subnet_after(
    subnet_str: &str,
    gateway_str: &str,
    existing: &HashMap<String, NetworkEndpoint>,
    last_ip: Option<&str>,
) -> Result<Ipv4Addr> {
    let (base_u32, bcast_u32) = parse_cidr_range(subnet_str)?;
    let gateway: Ipv4Addr = gateway_str.parse()?;

    let used_ips: Vec<Ipv4Addr> = existing
        .values()
        .filter_map(|e| e.ipv4_address.parse().ok())
        .collect();

    let start_host = base_u32 + 1;
    let end_host = bcast_u32.saturating_sub(1);
    if start_host > end_host {
        return Err(anyhow!(
            "No available IP addresses in subnet {}",
            subnet_str
        ));
    }

    let first_try = last_ip
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .map(u32::from)
        .filter(|&v| v >= start_host && v <= end_host)
        .map(|v| if v == end_host { start_host } else { v + 1 })
        .unwrap_or(start_host);

    let count = (end_host - start_host + 1) as u64;
    let span = (end_host - start_host + 1) as u64;
    let offset_start = (first_try - start_host) as u64;
    for step in 0..count {
        let host_int = start_host + ((offset_start + step) % span) as u32;
        let candidate = Ipv4Addr::from(host_int);
        if candidate != gateway && !used_ips.contains(&candidate) {
            return Ok(candidate);
        }
    }

    Err(anyhow!(
        "No available IP addresses in subnet {}",
        subnet_str
    ))
}

fn allocate_ip_in_subnet(
    subnet_str: &str,
    gateway_str: &str,
    existing: &HashMap<String, NetworkEndpoint>,
) -> Result<Ipv4Addr> {
    allocate_ip_in_subnet_after(subnet_str, gateway_str, existing, None)
}
