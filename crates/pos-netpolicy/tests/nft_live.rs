//! Writes real rule files for the CI job `netpolicy-nft` (see .github/workflows/netpolicy-nft.yml).
//! Ignored by default: it only writes files when POS_NFT_OUT_DIR is set, and never runs nft itself.
use pos_netpolicy::*;
use std::net::IpAddr;

#[test]
#[ignore = "used by the netpolicy-nft CI job"]
fn write_rule_files_for_ci() {
    let dir = std::env::var("POS_NFT_OUT_DIR").expect("POS_NFT_OUT_DIR");
    let uid: u32 = std::env::var("POS_NFT_UID")
        .expect("POS_NFT_UID")
        .parse()
        .unwrap();
    let w = |name: &str, body: String| std::fs::write(format!("{dir}/{name}"), body).unwrap();

    w("deny.nft", render_nft(&Policy::new(uid)).unwrap());

    let mut lo = Policy::new(uid);
    lo.allow_loopback = true;
    w("lo.nft", render_nft(&lo).unwrap());

    let mut full = Policy::new(uid);
    full.allow = vec![
        parse_target("203.0.113.0/24").unwrap(),
        parse_target("2001:db8::/32").unwrap(),
        parse_target("198.51.100.7").unwrap(),
    ];
    full.dns_resolver = Some("9.9.9.9".parse::<IpAddr>().unwrap());
    full.allow_loopback = true;
    full.allow_ipv6_nd = true;
    full.allow_dhcp = true;
    w("full.nft", render_nft(&full).unwrap());

    let mut full6 = full.clone();
    full6.dns_resolver = Some("2620:fe::fe".parse::<IpAddr>().unwrap());
    w("full6.nft", render_nft(&full6).unwrap());

    w("remove.nft", render_nft_remove());
    w(
        "unit.service",
        render_systemd_unit(
            "/usr/sbin/nft",
            "/etc/pos/netpolicy.nft",
            "/etc/pos/netpolicy-remove.nft",
        )
        .unwrap(),
    );
}
