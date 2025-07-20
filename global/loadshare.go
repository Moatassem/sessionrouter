package global

type WeightedHost struct {
	HostId            string
	Weight            int
	AccumulatedWeight int
	HitsCount         int
}

func GetRoutedHost(WeightedHostList []*WeightedHost) *WeightedHost {
	grandweight := 0
	for _, wh := range WeightedHostList {
		grandweight += wh.Weight
	}

	// assume 0th index as default
	hostWithMaxAccWeight := WeightedHostList[0]

	// choose the host with the greatest AccumWeight
	for i := len(WeightedHostList) - 1; i > 0; i-- {
		if WeightedHostList[i].AccumulatedWeight >= hostWithMaxAccWeight.AccumulatedWeight {
			hostWithMaxAccWeight = WeightedHostList[i]
		}
	}

	// deduct grandweight from the AccumWeight for the chosen host
	inverseAccWeight := hostWithMaxAccWeight.AccumulatedWeight - grandweight
	hostWithMaxAccWeight.AccumulatedWeight = inverseAccWeight

	// add Weight to AccumWeight for all hosts; including the chosen host
	for _, wh := range WeightedHostList {
		weight := wh.Weight
		accWeight := wh.AccumulatedWeight
		wh.AccumulatedWeight = weight + accWeight
	}

	return hostWithMaxAccWeight
}

func NewHW(hn string, wt int) *WeightedHost {
	return &WeightedHost{Weight: wt, HostId: hn, AccumulatedWeight: wt}
}

func GetTotalWeight(WeightedHostList []*WeightedHost) int {
	grandweight := 0
	for _, wh := range WeightedHostList {
		grandweight += wh.Weight
	}
	return grandweight
}

// func main1() {
// 	var lst []*WeightedHost

// 	lst = append(lst, NewHW("A", 8))
// 	lst = append(lst, NewHW("B", 1))
// 	lst = append(lst, NewHW("C", 1))

// 	totalAttempts := GetTotalWeight(lst)

// 	fmt.Printf("Result:\t")

// 	for i := 0; i < totalAttempts; i++ {
// 		// fmt.Printf("Attempt: %d", i+1)
// 		// for n := 0; n < len(lst); n++ {
// 		//  fmt.Printf("\t%s (%d)", lst[n].HostId, lst[n].AccumulatedWeight)
// 		// }
// 		wthost := GetRoutedHost(lst)
// 		wthost.HitsCount++
// 		fmt.Printf("%s", wthost.HostId)
// 	}

// 	fmt.Printf("\nTotal attempts: %d\n", totalAttempts)
// 	for _, wh := range lst {
// 		fmt.Printf("- %s: %d\n", wh.HostId, wh.HitsCount)
// 	}
// }
