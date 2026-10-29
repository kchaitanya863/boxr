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
    let (start1, end1) = parse_cidr_range(sub1)?;
    let (start2, end2) = parse_cidr_range(sub2)?;
    Ok(start1 <= end2 && start2 <= end1)
}

fn allocate_ip_in_subnet(
    subnet_str: &str,
    gateway_str: &str,
    existing: &HashMap<String, NetworkEndpoint>,
) -> Result<Ipv4Addr> {
    let (base_u32, bcast_u32) = parse_cidr_range(subnet_str)?;
    let gateway: Ipv4Addr = gateway_str.parse()?;

    let used_ips: Vec<Ipv4Addr> = existing
        .values()
        .filter_map(|e| e.ipv4_address.parse().ok())
        .collect();

    // Valid host range is from (base_u32 + 1) to (bcast_u32 - 1)
    let start_host = base_u32 + 1;
    let end_host = bcast_u32.saturating_sub(1);

    for host_int in start_host..=end_host {
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
