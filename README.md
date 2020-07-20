# `ssdp-probe`

A simple crate to perform SSDP discoveries

## Last version
```
ssdp-probe = "0.1"
```


## Usage
```rust
let addresses = ssdp_probe::ssdp_probe_v4(br"filter", // get only addresses that included this in their responses
                                          5, // stop when 5 addresses are found
                                          std::time::Duration::from_secs(5), // stop after 5s
                );

```

## License

### Apache 2.0/MIT

Licensed under either of
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or 
http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or 
http://opensource.org/licenses/MIT)

     at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
