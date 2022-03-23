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
)

// entryData contains the index / sequence number of an entry, as well as the
// leaf data contained at that index. It also implements the Orderable interface
// so that it can be used in a Heap.
type entryData struct {
	index int64
	entry ct.LogEntry
}

func (ed entryData) Before(other entryData) bool {
	return ed.index < other.index
}

func processEntry(prev, curr entryData) {
	if prev.entry.Leaf.TimestampedEntry.Timestamp > 10+curr.entry.Leaf.TimestampedEntry.Timestamp {
		fmt.Println("Found out-of-order entry:")
		fmt.Printf("Index: %d\n", prev.index)
		fmt.Printf("Timestamps: %d, %d\n", prev.entry.Leaf.TimestampedEntry.Timestamp, curr.entry.Leaf.TimestampedEntry.Timestamp)
		if prev.entry.X509Cert != nil {
			fmt.Printf("Serial: %d\n", prev.entry.X509Cert.SerialNumber)
		} else {
			fmt.Printf("Serial: %d\n", prev.entry.Precert.TBSCertificate.SerialNumber)
		}
		fmt.Println()
	}
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range batchChan {
				start := *startIndex + (b * (*batchSize))
				end := *startIndex + ((b+1)*(*batchSize) - 1)

				ctx := context.Background()
				entries, err := logClient.GetEntries(ctx, start, end)
				if err != nil {
					return
				}

				for i, entry := range entries {
					entryChan <- entryData{start + int64(i), entry}
				}
			}
		}()
	}

	// Create a goroutine which waits for all of the fetchers to finish their work
	// and then closes the channel they were writing to, so that the processing
	// goroutine also knows when to quit.
	go func() {
		wg.Wait()
		close(entryChan)
	}()

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
	for e := range entryChan {
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

		// Try to process the buffer, just in case we've caught up to it.
		for buffer.Len() > 0 && buffer.Peek().index == nextIndex {
			e = buffer.Pop()
			processEntry(last, e)
			last = e
			nextIndex += 1
		}
	}
}
