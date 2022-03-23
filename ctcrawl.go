package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
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

func main() {
	logURI := flag.String("log_uri", "https://oak.ct.letsencrypt.org/2022/", "CT log base URI")
	batchSize := flag.Int("batch_size", 256, "Max number of entries to request at per call to get-entries")
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

	fetcher := scanner.NewFetcher(
		logClient,
		&scanner.FetcherOptions{
			BatchSize:     *batchSize,
			StartIndex:    *startIndex,
			EndIndex:      *endIndex,
			ParallelFetch: *numWorkers,
			Continuous:    false,
		},
	)

	// Create a callback that sends fetched entries to a channel to be processed.
	entries := make(chan entryData)
	processBatch := func(batch scanner.EntryBatch) {
		for i, e := range batch.Entries {
			index := batch.Start + int64(i)
			rawLogEntry, err := ct.RawLogEntryFromLeaf(index, &e)
			if err != nil {
				fmt.Printf("failed to process entry at index %d: %v\n", index, err)
				continue
			}
			entries <- entryData{index: batch.Start + int64(i), entry: rawLogEntry}
		}
	}

	// Start a worker which reads entries from the fetchers. If it receives an
	// entry for which it has not already processed the immediately preceding
	// entry, it buffers it and waits to process it until the intervening entries
	// have been backfilled. When processing an entry, it compares it to the
	// immediately prior entry: if the timestamp has traveled backwards in time,
	// it outputs the *prior* entry, on the assumption that its timestamp was
	// incorrectly forward in time.
	buffer := NewHeap[entryData]()
	nextIndex := *startIndex
	last := entryData{index: -1}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range entries {
			// If it's not the entry we want, save it for later.
			if e.index != nextIndex {
				buffer.Push(e)
				continue
			}

			// If this is the first entry we're looking for, initialize our last-seen
			// tracker so we have a basis for comparison.
			if last.index == -1 {
				last = e
				nextIndex = e.index + 1
				continue
			}

			// This is the next entry we were looking for. Process it.
			processEntry(last, e)
			last = e
			nextIndex += 1
			if nextIndex%1000 == 0 {
				fmt.Printf("Processed up to index %d\n", nextIndex)
			}

			// Try to process the buffer, just in case we've caught up to it.
			for buffer.Len() > 0 && buffer.Peek().index == nextIndex {
				e = buffer.Pop()
				processEntry(last, e)
				last = e
				nextIndex += 1
				if nextIndex%1000 == 0 {
					fmt.Printf("Processed up to index %d\n", nextIndex)
				}
			}
		}
	}()

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

	// Finally, run the fetcher, letting it feed data into the worker above.
	err = fetcher.Run(ctx, processBatch)
	close(entries)
	wg.Wait()
	if err != nil {
		log.Fatal(err)
	}
}
