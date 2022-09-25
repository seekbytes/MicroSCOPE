package utils

import "math"

func CalculateEntropy(data []byte) float64 {
	// Calcolo entropia shannon
	// Fonte: http://bearcave.com/misl/misl_tech/wavelets/compression/shannon.html

	hist := make([]int, 256)
	for _, b := range data {
		hist[int(b)]++
	}

	size := len(data)
	var entropy = 0.0
	for _, count := range hist {
		if count == 0 {
			continue
		}
		entropy += (float64(count) / float64(size)) * math.Log2(float64(count)/float64(size))
	}

	if entropy != 0 {
		return -entropy
	} else {
		return 0
	}

}
