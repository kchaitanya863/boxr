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

pub fn parse_ipv6_cidr_range(subnet_str: &str) -> Result<(u128, u128)> {
    let (ip_part, mask_part) = subnet_str
        .split_once('/')
        .ok_or_else(|| anyhow!("Invalid IPv6 CIDR subnet {}", subnet_str))?;

    let base_ip: std::net::Ipv6Addr = ip_part.trim().parse()?;
    let prefix_len: u32 = mask_part
        .trim()
        .parse()
        .context("Invalid IPv6 CIDR prefix length")?;

    if prefix_len > 128 {
        return Err(anyhow!(
            "Unsupported IPv6 subnet prefix length /{}",
            prefix_len
        ));
    }

    let mask_u128 = if prefix_len == 0 {
        0
    } else {
        (!0u128) << (128 - prefix_len)
    };
    let base_u128 = u128::from(base_ip) & mask_u128;
    let end_u128 = base_u128 | (!mask_u128);
    Ok((base_u128, end_u128))
}

pub fn canonicalize_subnet_and_gateway(subnet_str: &str) -> Result<(String, String)> {
    let trimmed = subnet_str.trim();
    if trimmed.contains(':') {
        let (_, mask_part) = trimmed
            .split_once('/')
            .ok_or_else(|| anyhow!("Invalid IPv6 CIDR subnet {}", trimmed))?;
        let prefix_len: u32 = mask_part.trim().parse()?;
        let (base_u128, _) = parse_ipv6_cidr_range(trimmed)?;
        let net_ip = std::net::Ipv6Addr::from(base_u128);
        let gw_ip = std::net::Ipv6Addr::from(base_u128.saturating_add(1));
        Ok((format!("{}/{}", net_ip, prefix_len), gw_ip.to_string()))
    } else {
        let (_, mask_part) = trimmed
            .split_once('/')
            .ok_or_else(|| anyhow!("Invalid CIDR subnet {}", trimmed))?;
        let prefix_len: u32 = mask_part.trim().parse()?;
        let (base_u32, _) = parse_cidr_range(trimmed)?;
        let net_ip = Ipv4Addr::from(base_u32);
        let gw_ip = Ipv4Addr::from(base_u32.saturating_add(1));
        Ok((format!("{}/{}", net_ip, prefix_len), gw_ip.to_string()))
    }
}

pub fn ip_in_subnet(ip_str: &str, subnet_str: &str) -> bool {
    let ip_t = ip_str.trim();
    let sub_t = subnet_str.trim();
    if ip_t.contains(':') != sub_t.contains(':') {
        return false;
    }
    if ip_t.contains(':') {
        if let (Ok(ip), Ok((start, end))) = (
            ip_t.parse::<std::net::Ipv6Addr>(),
            parse_ipv6_cidr_range(sub_t),
        ) {
            let v = u128::from(ip);
            v >= start && v <= end
        } else {
            false
        }
    } else if let (Ok(ip), Ok((start, end))) =
        (ip_t.parse::<Ipv4Addr>(), parse_cidr_range(sub_t))
    {
        let v = u32::from(ip);
        v >= start && v <= end
    } else {
        false
    }
}

pub fn allocate_ipv6_in_subnet(
    subnet_str: &str,
    gateway_str: &str,
    used_ips: &[String],
) -> Result<String> {
    let (base_u128, end_u128) = parse_ipv6_cidr_range(subnet_str)?;
    let gw_opt = gateway_str.trim().parse::<std::net::Ipv6Addr>().ok();
    for offset in 2u128..1000u128 {
        let cand_u128 = base_u128.saturating_add(offset);
        if cand_u128 >= end_u128 {
            break;
        }
        let cand = std::net::Ipv6Addr::from(cand_u128);
        if Some(cand) == gw_opt {
            continue;
        }
        let cand_str = cand.to_string();
        if !used_ips.iter().any(|u| u == &cand_str) {
            return Ok(cand_str);
        }
    }
    Err(anyhow!(
        "No available IPv6 addresses in subnet {}",
        subnet_str
    ))
}

pub fn subnets_overlap(sub1: &str, sub2: &str) -> Result<bool> {
    let v6_1 = sub1.contains(':');
    let v6_2 = sub2.contains(':');
    if v6_1 != v6_2 {
        return Ok(false);
    }
    if v6_1 {
        let (start1, end1) = parse_ipv6_cidr_range(sub1)?;
        let (start2, end2) = parse_ipv6_cidr_range(sub2)?;
        return Ok(start1 <= end2 && start2 <= end1);
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
