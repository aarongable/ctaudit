package main

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian/client/backoff"
)

// entryData contains the index / sequence number of an entry, as well as the
// leaf data contained at that index. It also implements the Orderable interface
// so that it can be used in a Heap.
type entryData struct {
	index int64
	entry *ct.RawLogEntry
}

func (ed entryData) Before(other entryData) bool {
	return ed.index < other.index
}

func processEntry(prev, curr entryData) {
	if prev.entry.Leaf.TimestampedEntry.Timestamp > 1000+curr.entry.Leaf.TimestampedEntry.Timestamp {
		fmt.Println("Found out-of-order entry:")
		fmt.Printf("  Index: %d\n", prev.index)
		fmt.Printf("  Timestamps: %d, %d\n", prev.entry.Leaf.TimestampedEntry.Timestamp, curr.entry.Leaf.TimestampedEntry.Timestamp)
		switch prev.entry.Leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			cert, err := prev.entry.Leaf.X509Certificate()
			if err != nil {
				fmt.Printf("  Failed to parse: %v\n", err)
			} else {
				fmt.Printf("  Serial: %d\n", cert.SerialNumber)
			}
		case ct.PrecertLogEntryType:
			cert, err := prev.entry.Leaf.Precertificate()
			if err != nil {
				fmt.Printf("  Failed to parse: %v\n", err)
			} else {
				fmt.Printf("  Serial: %d\n", cert.SerialNumber)
			}
		}
	}
}

type candidateEntry struct {
	Index     int64
	Timestamp uint64
	Serial    *big.Int
}

func main() {
	entryFile := flag.String("entry_file", "", "Path to CSV of entries to compare")
	leafdataFile := flag.String("leafdata_file", "", "Path to output CSV of mismatched leafdata")
	logURI := flag.String("log_uri", "https://oak.ct.letsencrypt.org/2022/", "CT log base URI")
	numWorkers := flag.Int("num_workers", 2, "Number of concurrent workers")
	flag.Parse()

	// Open the files so we can bail out early if that fails.
	infile, err := os.Open(*entryFile)
	if err != nil {
		log.Fatal(err)
	}

	outfile, err := os.Create(*leafdataFile)
	if err != nil {
		log.Fatal(err)
	}

	// Set up a context and a signal-catcher to cancel the context so we can
	// break out cleanly if we need to.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)
		signal.Notify(sigChan, syscall.SIGINT)
		signal.Notify(sigChan, syscall.SIGHUP)

		<-sigChan
		cancel()

		os.Exit(0)
	}()

	// Kick off a worker which reads lines from the CSV file and sends them to a
	// channel for other workers to process.
	r := csv.NewReader(infile)
	r.FieldsPerRecord = 4
	r.TrimLeadingSpace = true
	candidates := make(chan candidateEntry)
	go func() {
		for {
			e, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatal(err)
			}

			index, err := strconv.ParseInt(e[0], 10, 64)
			if err != nil {
				log.Fatal(err)
			}

			time_millis, err := strconv.ParseUint(e[1], 10, 64)
			if err != nil {
				log.Fatal(err)
			}

			serial := new(big.Int)
			serial, ok := serial.SetString(e[3], 10)
			if !ok {
				log.Fatal("failed to conver serial to bigint")
			}

			candidates <- candidateEntry{index, time_millis, serial}
		}
		close(candidates)
	}()

	// Kick off workers that read from the entries channel and query the given
	// log for the same entry.
	logClient, err := client.New(*logURI, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, jsonclient.Options{UserAgent: "le-ct-crawler/0.1"})
	if err != nil {
		log.Fatal("Failed to create log client")
	}

	bo := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    30 * time.Second,
		Factor: 2,
		Jitter: true,
	}

	output := csv.NewWriter(outfile)

	var wg sync.WaitGroup
	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range candidates {
				var r []ct.LogEntry
				err := bo.Retry(ctx, func() error {
					var err error
					r, err = logClient.GetEntries(ctx, c.Index, c.Index)
					return err
				})
				if err != nil {
					log.Fatal(err)
				}
				if len(r) != 1 {
					log.Fatal("got wrong number of entries from log")
				}
				entry := r[0]

				if entry.Leaf.TimestampedEntry.Timestamp == c.Timestamp {
					continue
				}

				fmt.Printf("Found mismatch:\n")
				fmt.Printf("  Index: %d\n", c.Index)
				fmt.Printf("  Orig TS: %d\n", entry.Leaf.TimestampedEntry.Timestamp)
				fmt.Printf("  Dupl TS: %d\n", c.Timestamp)

				leaf_input, err := tls.Marshal(entry.Leaf)
				if err != nil {
					log.Fatal("Failed to marshal leaf_input")
				}
				output.Write([]string{fmt.Sprintf("%d", c.Index), hex.EncodeToString(leaf_input)})
			}
		}()
	}

	wg.Wait()
	output.Flush()
}
