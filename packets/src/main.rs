use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::prelude::*;

// ----------------- ip address ----------------- //

fn ip_address(file_path: &str) -> Vec<String> {
    let mut file: File = File::open(file_path).expect("Failed to open file");
    let mut contents: String = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    let packet: Value = serde_json::from_str(&contents).unwrap();
    let mut ip_addresses: HashSet<String> = HashSet::new();
    for packet in packet.as_array().unwrap() {
        match packet["_source"]["layers"]["ip"].get("ip.src") {
            Some(e) => {
                let ip_address = e.to_string();
                ip_addresses.insert(ip_address);
            }
            None => {
                continue;
            }
        };
        match packet["_source"]["layers"]["ip"].get("ip.dst") {
            Some(e) => {
                let ip_address = e.to_string();
                ip_addresses.insert(ip_address);
            }
            None => {
                continue;
            }
        };
    }

    let ip_addresses_vec: Vec<String> = ip_addresses.into_iter().collect();
    let ip_addresses_clean: Vec<String> = ip_addresses_vec
        .iter()
        .map(|s| s.replace("\"", "").replace("\\", ""))
        .collect();
    return ip_addresses_clean;
}

// ----------------- http ----------------- //

fn http(file_path: &str) -> Vec<String> {
    let mut file: File = File::open(file_path).expect("Failed to open file");
    let mut contents: String = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    let packet: Value = serde_json::from_str(&contents).unwrap();
    let mut http: HashSet<String> = HashSet::new();

    for packet in packet.as_array().unwrap() {
        match packet["_source"]["layers"]["http"].get("http.host") {
            Some(e) => {
                let http_host = e.to_string();
                http.insert(http_host);
            }
            None => {
                continue;
            }
        };
        match packet["_source"]["layers"]["http"].get("http.request.full_uri") {
            Some(e) => {
                let http_request_full_uri = e.to_string();
                http.insert(http_request_full_uri);
            }
            None => {
                continue;
            }
        };
        match packet["_source"]["layers"]["http"].get("http.request.method") {
            Some(e) => {
                let http_request_method = e.to_string();
                http.insert(http_request_method);
            }
            None => {
                continue;
            }
        };
        match packet["_source"]["layers"]["http"].get("http.user_agent") {
            Some(e) => {
                let http_user_agent = e.to_string();
                http.insert(http_user_agent);
            }
            None => {
                continue;
            }
        };
    }

    let http_vec: Vec<String> = http.into_iter().collect();
    let http_clean: Vec<String> = http_vec
        .iter()
        .map(|s| s.replace("\"", "").replace("\\", ""))
        .collect();
    return http_clean;
}

// ----------------- mac address ----------------- //

fn mac_address(file_path: &str) -> Vec<String> {
    let mut file: File = File::open(file_path).expect("Failed to open file");
    let mut contents: String = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    let packet: Value = serde_json::from_str(&contents).unwrap();
    let mut mac_addresses: HashSet<String> = HashSet::new();
    for packet in packet.as_array().unwrap() {
        match packet["_source"]["layers"]["eth"].get("eth.src") {
            Some(e) => {
                let mac_address = e.to_string();
                mac_addresses.insert(mac_address);
            }
            None => {
                continue;
            }
        };
        match packet["_source"]["layers"]["eth"].get("eth.dst") {
            Some(e) => {
                let mac_address = e.to_string();
                mac_addresses.insert(mac_address);
            }
            None => {
                continue;
            }
        };
    }

    let mac_addresses_vec: Vec<String> = mac_addresses.into_iter().collect();
    let mac_addresses_clean: Vec<String> = mac_addresses_vec
        .iter()
        .map(|s| s.replace("\"", "").replace("\\", ""))
        .collect();
    return mac_addresses_clean;
}

// ----------------- tcp ----------------- //

fn tcp(file_path: &str) -> Vec<String> {
    let mut file: File = File::open(file_path).expect("Failed to open file");
    let mut contents: String = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    let packet: Value = serde_json::from_str(&contents).unwrap();
    let mut tcp_ports: HashSet<String> = HashSet::new();
    for packet in packet.as_array().unwrap() {
        match packet["_source"]["layers"]["tcp"].get("tcp.port") {
            Some(e) => {
                let tcp_port = e.to_string();
                tcp_ports.insert(tcp_port);
            }
            None => {
                continue;
            }
        };
    }

    let tcp_ports_vec: Vec<String> = tcp_ports.into_iter().collect();
    let tcp_ports_clean: Vec<String> = tcp_ports_vec
        .iter()
        .map(|s| s.replace("\"", "").replace("\\", ""))
        .collect();
    return tcp_ports_clean;
}

// ----------------- udp ----------------- //

fn udp(file_path: &str) -> Vec<String> {
    let mut file: File = File::open(file_path).expect("Failed to open file");
    let mut contents: String = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    let packet: Value = serde_json::from_str(&contents).unwrap();
    let mut udp_ports: HashSet<String> = HashSet::new();
    for packet in packet.as_array().unwrap() {
        match packet["_source"]["layers"]["udp"].get("udp.port") {
            Some(e) => {
                let udp_port = e.to_string();
                udp_ports.insert(udp_port);
            }
            None => {
                continue;
            }
        };
    }

    let udp_ports_vec: Vec<String> = udp_ports.into_iter().collect();
    let udp_ports_clean: Vec<String> = udp_ports_vec
        .iter()
        .map(|s| s.replace("\"", "").replace("\\", ""))
        .collect();
    return udp_ports_clean;
}

// ----------------- main ----------------- //

fn main() -> std::io::Result<()> {
    let cwd = env::current_dir()?;
    let path = cwd.join("packets.json");
    let file_path: &str = path.to_str().unwrap();

    let tcp_ports: Vec<String> = tcp(file_path);
    let udp_ports: Vec<String> = udp(file_path);
    let ip_addresses: Vec<String> = ip_address(file_path);
    let mac_addresses: Vec<String> = mac_address(file_path);
    let http: Vec<String> = http(file_path);
    // let dns: Vec<String> = dns(file_path);

    println!("{:?}", tcp_ports);
    println!("{:?}", udp_ports);
    println!("{:?}", ip_addresses);
    println!("{:?}", mac_addresses);
    println!("{:?}", http);
    // println!("{:?}", dns);
    Ok(())
}
