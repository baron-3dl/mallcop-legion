package baseline

import (
	"encoding/json"
	"os"
	"time"
)

// Baseline holds historical login patterns for known users.
type Baseline struct {
	KnownUsers map[string]UserProfile `json:"known_users"`
}

// UserProfile captures the expected behaviour for a single actor.
type UserProfile struct {
	KnownIPs  []string  `json:"known_ips"`
	KnownGeos []string  `json:"known_geos"` // e.g. "US", "GB"
	LastSeen  time.Time `json:"last_seen"`
}

// Load reads and parses a baseline JSON file from disk.
func Load(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var b Baseline
	if err := json.NewDecoder(f).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// HasUser returns true when the actor appears in the baseline.
func (b *Baseline) HasUser(actor string) bool {
	_, ok := b.KnownUsers[actor]
	return ok
}

// KnownIP returns true when the IP is in the actor's profile.
func (b *Baseline) KnownIP(actor, ip string) bool {
	p, ok := b.KnownUsers[actor]
	if !ok {
		return false
	}
	for _, known := range p.KnownIPs {
		if known == ip {
			return true
		}
	}
	return false
}

// KnownGeo returns true when the geo is in the actor's profile.
func (b *Baseline) KnownGeo(actor, geo string) bool {
	p, ok := b.KnownUsers[actor]
	if !ok {
		return false
	}
	for _, known := range p.KnownGeos {
		if known == geo {
			return true
		}
	}
	return false
}
