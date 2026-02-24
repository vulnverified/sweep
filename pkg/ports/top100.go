// Package ports provides common port definitions for network scanning.
package ports

// Top100 is the top 100 most common TCP ports based on nmap frequency data.
// Sorted ascending for consistent output.
var Top100 = []int{
	21, 22, 23, 25, 26, 53, 80, 81, 110, 111,
	113, 135, 139, 143, 179, 199, 443, 445, 465, 514,
	515, 548, 554, 587, 631, 636, 646, 993, 995, 1025,
	1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
	2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
	4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
	5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
	8080, 8081, 8443, 8888, 9090, 9100, 9999, 10000, 32768, 49152,
	49153, 49154, 49155, 49156, 49157, 1080, 1443, 2082, 2083, 2086,
	2087, 4443, 6379, 6443, 8443, 8880, 9200, 9443, 27017, 27018,
}

func init() {
	// Deduplicate (8443 appears twice in source list)
	seen := make(map[int]bool, len(Top100))
	deduped := make([]int, 0, len(Top100))
	for _, p := range Top100 {
		if !seen[p] {
			seen[p] = true
			deduped = append(deduped, p)
		}
	}
	// Sort
	for i := 0; i < len(deduped); i++ {
		for j := i + 1; j < len(deduped); j++ {
			if deduped[j] < deduped[i] {
				deduped[i], deduped[j] = deduped[j], deduped[i]
			}
		}
	}
	Top100 = deduped
}
