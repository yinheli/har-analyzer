# har analyzer

## Motivation

When config [kungfu](https://github.com/yinheli/kungfu) rules, we need to analyze which domain/url is slow or blocked. So I build this tool to analysis the HAR file which export from browser.

## Usage

```bash
$ har-analyzer analysis --help

Analysis har file to get domain list with additional information

Usage: har-analyzer analysis [OPTIONS]

Options:
  -f, --har <HAR>  har file [default: ./har.har]
  -d, --dns <DNS>  dns server, default use system
      --verbose    Verbose log
  -h, --help       Print help information
  -V, --version    Print version information
```
