use std::{
    fs::{self, File},
    io::Write,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Error};
use log::info;
use ping::ping;
use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};
use tabled::Tabled;
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Resolver,
};
use url::Url;

#[derive(Debug)]
pub struct Record {
    domain: String,
    addrs: Vec<IpAddr>,
    latency: Duration,
    geo: String,
    err: Option<String>,
}

impl Record {
    pub fn to_tabled(&self) -> TabledRecord {
        TabledRecord::from(self)
    }

    fn new(domain: String) -> Self {
        Self {
            domain,
            addrs: vec![],
            latency: Default::default(),
            geo: "".to_string(),
            err: None,
        }
    }

    fn analysis(&mut self, resolver: &Resolver, geo_ip_reader: &maxminddb::Reader<Vec<u8>>) {
        match self.lookup(resolver) {
            Ok(addrs) => self.addrs = addrs,
            Err(err) => {
                self.err = Some(format!("{}", err));
                return;
            }
        }

        if !self.addrs.is_empty() {
            match self.latency(*self.addrs.first().unwrap()) {
                Ok(d) => self.latency = d,
                Err(err) => {
                    self.err = Some(format!("{}", err));
                }
            }

            if let Ok(addr) = self.geoip(geo_ip_reader, &self.addrs) {
                self.geo = addr.join("\n");
            }
        }
    }

    fn lookup(&self, resolver: &Resolver) -> Result<Vec<IpAddr>, Error> {
        let result = resolver.lookup_ip(&self.domain)?;
        Ok(result.iter().collect::<Vec<_>>())
    }

    fn latency(&self, addr: IpAddr) -> Result<Duration, Error> {
        let now = Instant::now();
        let r = ping(
            addr,
            Some(Duration::from_secs(2)),
            Some(64),
            None,
            None,
            None,
        );

        match r {
            Ok(_) => Ok(now.elapsed()),
            Err(e) => Err(anyhow!("{:?}", e)),
        }
    }

    fn geoip(
        &self,
        geo_ip_reader: &maxminddb::Reader<Vec<u8>>,
        addrs: &Vec<IpAddr>,
    ) -> Result<Vec<String>, Error> {
        let mut buf = vec![];

        for addr in addrs {
            let mut v = vec![];
            let r: maxminddb::geoip2::City = geo_ip_reader.lookup(*addr)?;
            if let Some(country) = r.country {
                v.push(country.names.unwrap().get("en").unwrap_or(&"").to_string());
            }

            if let Some(city) = r.city {
                v.push(city.names.unwrap().get("en").unwrap_or(&"").to_string());
            }

            v.dedup();

            buf.push(v.join(" / "));
        }

        Ok(buf)
    }
}

pub fn analysis(file_path: &str, dns_server: Option<String>) -> Result<Vec<Record>, Error> {
    let resolver = build_resolve(dns_server)?;
    let reader = build_geoip_reader()?;

    let domains = get_domains(file_path)?;
    let mut records = build_records(domains);

    records.par_iter_mut().for_each(|v| {
        v.analysis(&resolver, &reader);
    });

    Ok(records)
}

fn build_resolve(dns_server: Option<String>) -> Result<Resolver, Error> {
    let mut resolver = Resolver::from_system_conf()?;

    if let Some(dns_server) = dns_server {
        let mut ip_addr: &str = &dns_server;
        let mut port = 53;
        if let Some(i) = dns_server.find(':') {
            ip_addr = &dns_server[..i];
            port = dns_server[i + 1..].parse()?;
        }
        let addr = ip_addr.parse()?;

        let socket_addr = SocketAddr::new(addr, port);
        let name_server = NameServerConfig::new(socket_addr, Protocol::Udp);

        let mut config = ResolverConfig::new();
        config.add_name_server(name_server);

        resolver = Resolver::new(config, ResolverOpts::default())?;
    }

    Ok(resolver)
}

fn build_geoip_reader() -> Result<maxminddb::Reader<Vec<u8>>, Error> {
    let home = dirs::home_dir().unwrap();
    let dir = home.join(".geolete2");
    let file_path = dir.join("GeoLite2-City.mmdb");

    if !file_path.exists() {
        fs::create_dir_all(dir)?;
        info!("downloading GeoLite2-City.mmdb");
        let response = reqwest::blocking::get(
            "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
        )?;
        let mut file = File::create(file_path.clone())?;
        let data = response.bytes()?.to_vec();
        file.write_all(&data)?;
        file.flush()?;
    }

    Ok(maxminddb::Reader::open_readfile(file_path)?)
}

fn get_domains(file_path: &str) -> Result<Vec<String>, Error> {
    let har = har::from_path(file_path)?;

    let urls = match har.log {
        har::Spec::V1_2(l) => l
            .entries
            .iter()
            .map(|v| v.request.url.clone())
            .collect::<Vec<_>>(),
        har::Spec::V1_3(l) => l
            .entries
            .iter()
            .map(|v| v.request.url.clone())
            .collect::<Vec<_>>(),
    };

    let mut domains = urls
        .iter()
        .map(|v| match Url::parse(v) {
            Ok(v) => Some(String::from(v.host_str().unwrap())),
            Err(_) => None,
        })
        .filter(|v| v.is_some())
        .flatten()
        .collect::<Vec<_>>();

    domains.sort();
    domains.dedup();

    Ok(domains)
}

fn build_records(domains: Vec<String>) -> Vec<Record> {
    domains
        .iter()
        .map(|v| Record::new(String::from(v)))
        .collect()
}

#[derive(Tabled)]
pub struct TabledRecord {
    domain: String,
    addrs: String,
    latency: String,
    geo: String,
    err: String,
}

impl From<&Record> for TabledRecord {
    fn from(r: &Record) -> Self {
        let addrs = r
            .addrs
            .iter()
            .map(|v| format!("{}", v))
            .collect::<Vec<String>>()
            .join("\n");

        let latency = format!("{}ms", r.latency.as_millis());

        Self {
            domain: r.domain.clone(),
            addrs,
            latency,
            geo: r.geo.clone(),
            err: r.err.clone().or_else(|| Some("".to_string())).unwrap(),
        }
    }
}
