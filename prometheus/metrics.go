package prometheus

import (
	"net/http"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all the custom Prometheus metrics for the application.
type Metrics struct {
	Registry    *prometheus.Registry
	ConSessions prometheus.Gauge
	Caps        prometheus.Gauge
}

// NewMetrics initializes a new custom Prometheus registry and returns an instance of Metrics.
func NewMetrics(ua string) *Metrics {
	// drop "/1.0"
	ua = strings.Split(ua, "/")[0]

	reg := prometheus.NewRegistry()

	// Register default Go runtime metrics
	reg.MustRegister(collectors.NewGoCollector())

	opts := collectors.ProcessCollectorOpts{
		PidFn:        func() (int, error) { return os.Getpid(), nil },
		Namespace:    ua,
		ReportErrors: true, // or false, depending on your needs
	}
	reg.MustRegister(collectors.NewProcessCollector(opts))

	// Initialize custom metrics here, e.g.:
	caps := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: ua,
		Name:      "CallAttemptsPerSecond",
		Help:      "Shows current CAPS",
	})
	reg.MustRegister(caps)

	concurrentSessions := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: ua,
		Name:      "ConcurrentSessions",
		Help:      "Shows concurrent sessions active",
	})
	reg.MustRegister(concurrentSessions)

	metrics := &Metrics{
		Registry:    reg,
		ConSessions: concurrentSessions,
		Caps:        caps,
	}

	return metrics
}

// Handler returns an HTTP handler that serves the metrics on a specified endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
