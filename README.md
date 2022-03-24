# ctcrawl

A utility for quickly crawling a whole CT log and outputting various data from it.

## Usage

```sh
go run ./crawl -log_uri https://oak.ct.letsencrypt.org/2022/ -num_workers 100 -start_index 0 -end_index 10000
```

```sh
go run ./compare -log_uri https://ct.googleapis.com/logs/mirror/eu1/letsencrypt_oak2022/ -entry_file candidates.csv -leafdata_file output.csv
```
