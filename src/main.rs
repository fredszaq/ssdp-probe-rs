fn main() {
    #[cfg(feature = "envlogger")]
    pretty_env_logger::init();

    let marker = std::env::args().nth(1).unwrap_or("200 OK".into());

    let results_ipv4 =
        ssdp_probe::ssdp_probe_v4(marker.as_bytes(), 100, std::time::Duration::from_secs(5));
    let results_ipv6 =
        ssdp_probe::ssdp_probe_v6(marker.as_bytes(), 100, std::time::Duration::from_secs(5));

    println!("results ipv4: {:?}", results_ipv4,);

    println!("results ipv6: {:?}", results_ipv6,);
}
