package psfp

import (
	"sort"
	"sync"
)

// parallel runs fn(0..n-1) across at most c.conc workers and waits for all.
func (c *Client) parallel(n int, fn func(i int)) {
	if n == 0 {
		return
	}
	conc := c.conc
	if conc > n {
		conc = n
	}
	jobs := make(chan int, n)
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func sortStrings(s []string) { sort.Strings(s) }

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
