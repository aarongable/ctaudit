package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
)

type entryData struct {
	index int64
	entry ct.MerkleTreeLeaf
}

func main() {
	logURI := flag.String("log_uri", "https://oak.ct.letsencrypt.org/2022/", "CT log base URI")
	batchSize := flag.Int64("batch_size", 256, "Max number of entries to request at per call to get-entries")
	numWorkers := flag.Int("num_workers", 2, "Number of concurrent workers")
	startIndex := flag.Int64("start_index", 0, "Log index to start scanning at")
	endIndex := flag.Int64("end_index", 0, "Log index to end scanning at (non-inclusive, 0 = end of log)")
	flag.Parse()

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

	// Create a channel that just counts up from zero to the total number of
	// batches that we'll have to request to cover the whole index space.
	batchChan := make(chan int64)
	go func() {
		for i := int64(0); i <= (*endIndex-*startIndex)/(*batchSize); i++ {
			batchChan <- i
		}
		close(batchChan)
	}()

	// Create a collection of channels that all fetch batches of entries from the
	// log, parse the leaf data (but not the actual certificates) in each entry,
	// and send that data to an output channel.
	var wg sync.WaitGroup
	entryChan := make(chan entryData)
	for w := 0; w < *numWorkers; w++ {
		go func() {
			defer wg.Done()
			for b := range batchChan {
				start := b * (*batchSize)
				end := (b+1)*(*batchSize) - 1

				ctx := context.Background()
				entries, err := logClient.GetRawEntries(ctx, start, end)
				if err != nil {
					return
				}

				for i, entry := range entries.Entries {
					leaf := ct.MerkleTreeLeaf{}
					_, err := tls.Unmarshal(entry.LeafInput, &leaf)
					if err != nil {
						return
					}

					entryChan <- entryData{index: start + int64(i), entry: leaf}
				}
			}
		}()
		wg.Add(1)
	}

	// Start a worker which reads entries and logs them to disk.
	// TODO: Actually write to disk, buffer and sort the output before doing so.
	go func() {
		for e := range entryChan {
			fmt.Printf("%d, %d\n", e.index, e.entry.TimestampedEntry.Timestamp)
		}
	}()

	wg.Wait()
}
