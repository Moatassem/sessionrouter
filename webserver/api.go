package webserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	. "SRGo/global"
	"SRGo/phone"
	"SRGo/sip"
)

func StartWS() {
	r := http.NewServeMux()
	ws := fmt.Sprintf("%s:%d", sip.ServerIPv4, HttpTcpPort)
	srv := &http.Server{Addr: ws, Handler: r, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}

	wireAPIPathHandlers(r)

	WtGrp.Add(1)
	go func() {
		defer WtGrp.Done()
		log.Fatal(srv.ListenAndServe())
	}()

	fmt.Print("Loading API Webserver...")
	fmt.Println("Success: HTTP", ws)

	fmt.Printf("Prometheus metrics available at http://%s/metrics\n", ws)

	fmt.Println("SRGo is ready to serve!")
}

func wireAPIPathHandlers(r *http.ServeMux) {
	r.HandleFunc("GET /api/v1/session", serveSession)
	r.HandleFunc("GET /api/v1/phone", servePhone)
	r.HandleFunc("GET /api/v1/stats", serveStats)
	r.HandleFunc("GET /api/v1/config", serveConfig)
	r.HandleFunc("PATCH /api/v1/config", refreshConfig)

	r.Handle("GET /metrics", Prometrics.Handler())
	r.HandleFunc("GET /", serveHome)
}

func serveHome(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write(fmt.Appendf(nil, "<h1>%s API Webserver</h1>\n", B2BUANameVersion))
}

func serveSession(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/text")

	response, _ := json.Marshal(sip.Sessions.Summaries())
	_, err := w.Write(response)
	if err != nil {
		LogError(LTWebserver, err.Error())
	}
}

func serveStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	BToMB := func(b uint64) uint64 {
		return b / 1000 / 1000
	}

	data := struct {
		CPUCount        int
		GoRoutinesCount int
		Alloc           uint64
		System          uint64
		GCCycles        uint32
		WaitGroupLength int
		SessionsCount   int
	}{
		CPUCount:        runtime.NumCPU(),
		GoRoutinesCount: runtime.NumGoroutine(),
		Alloc:           BToMB(m.Alloc),
		System:          BToMB(m.Sys),
		GCCycles:        m.NumGC,
		WaitGroupLength: sip.WorkerCount + 3,
		SessionsCount:   sip.Sessions.Count(),
	}

	response, _ := json.Marshal(data)
	_, err := w.Write(response)
	if err != nil {
		LogError(LTWebserver, err.Error())
	}
}

func servePhone(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	phones := phone.Phones.All()

	response, _ := json.Marshal(phones)
	_, err := w.Write(response)
	if err != nil {
		LogError(LTWebserver, err.Error())
	}
}

func serveConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	data, err := sip.RoutingEngineDB.MarshalJSON()
	if err != nil {
		LogError(LTWebserver, err.Error())
		http.Error(w, "Failed to marshal routing data", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(data)
}

func refreshConfig(w http.ResponseWriter, _ *http.Request) {
	sip.RoutingEngineDB.ReloadConfig()
	_, _ = w.Write(fmt.Appendf(nil, "<h1>%s API Webserver - Config reloaded successfully</h1>\n", B2BUANameVersion))
}
