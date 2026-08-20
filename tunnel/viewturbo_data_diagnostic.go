package tunnel

import (
	"sync/atomic"

	"github.com/metacubex/mihomo/log"
)

var (
	tunTCPIn          atomic.Uint64
	tunUDPIn          atomic.Uint64
	dispatchResolved  atomic.Uint64
	dispatchDialOK    atomic.Uint64
	dispatchDialError atomic.Uint64
)

func recordTunTCPIn() {
	value := tunTCPIn.Add(1)
	if value == 1 {
		log.Infoln("[ViewTurbo] phase=tun_data tcp_in=%d udp_in=%d dispatch_resolved=%d dial_success=%d dial_failure=%d", value, tunUDPIn.Load(), dispatchResolved.Load(), dispatchDialOK.Load(), dispatchDialError.Load())
	}
}

func recordTunUDPIn() {
	value := tunUDPIn.Add(1)
	if value == 1 {
		log.Infoln("[ViewTurbo] phase=tun_data tcp_in=%d udp_in=%d dispatch_resolved=%d dial_success=%d dial_failure=%d", tunTCPIn.Load(), value, dispatchResolved.Load(), dispatchDialOK.Load(), dispatchDialError.Load())
	}
}

func recordDispatchResolved() {
	value := dispatchResolved.Add(1)
	if value == 1 {
		log.Infoln("[ViewTurbo] phase=tun_data tcp_in=%d udp_in=%d dispatch_resolved=%d dial_success=%d dial_failure=%d", tunTCPIn.Load(), tunUDPIn.Load(), value, dispatchDialOK.Load(), dispatchDialError.Load())
	}
}

func recordDispatchDial(success bool) {
	if success {
		value := dispatchDialOK.Add(1)
		if value == 1 {
			log.Infoln("[ViewTurbo] phase=tun_data tcp_in=%d udp_in=%d dispatch_resolved=%d dial_success=%d dial_failure=%d", tunTCPIn.Load(), tunUDPIn.Load(), dispatchResolved.Load(), value, dispatchDialError.Load())
		}
		return
	}
	value := dispatchDialError.Add(1)
	if value == 1 {
		log.Infoln("[ViewTurbo] phase=tun_data tcp_in=%d udp_in=%d dispatch_resolved=%d dial_success=%d dial_failure=%d", tunTCPIn.Load(), tunUDPIn.Load(), dispatchResolved.Load(), dispatchDialOK.Load(), value)
	}
}
