package baseline

import (
	"encoding/json"
	"os"
	"time"
)

// Baseline holds historical patterns for known users and entities.
type Baseline struct {
	KnownUsers map[string]UserProfile `json:"known_users"`

	// KnownActors is the set of actors seen during the baseline window.
	// Used by detector-new-actor.
	KnownActors []string `json:"known_actors,omitempty"`

	// FrequencyTables maps "source:event_type" → baseline event count.
	// Used by detector-volume-anomaly.
	FrequencyTables map[string]int `json:"frequency_tables,omitempty"`

	// ActorHours maps actor → list of UTC hours (0-23) seen during baseline.
	// Used by detector-unusual-timing.
	ActorHours map[string][]int `json:"actor_hours,omitempty"`

	// ActorRoles maps actor → list of known role/permission keys.
	// Used by detector-priv-escalation.
	ActorRoles map[string][]string `json:"actor_roles,omitempty"`
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

// IsKnownActor returns true when the actor appears in KnownActors.
func (b *Baseline) IsKnownActor(actor string) bool {
	for _, a := range b.KnownActors {
		if a == actor {
			return true
		}
	}
	return false
}

// FreqCount returns the baseline event count for "source:event_type".
func (b *Baseline) FreqCount(source, eventType string) int {
	if b.FrequencyTables == nil {
		return 0
	}
	return b.FrequencyTables[source+":"+eventType]
}

// KnownHour returns true when the given UTC hour is in the actor's known hours.
func (b *Baseline) KnownHour(actor string, hour int) bool {
	hours, ok := b.ActorHours[actor]
	if !ok {
		return false
	}
	for _, h := range hours {
		if h == hour {
			return true
		}
	}
	return false
}

// HasActorHours returns true when there is any timing baseline data.
func (b *Baseline) HasActorHours() bool {
	return len(b.ActorHours) > 0
}

// IsKnownRole returns true when actor+role is in the actor roles baseline.
func (b *Baseline) IsKnownRole(actor, role string) bool {
	roles, ok := b.ActorRoles[actor]
	if !ok {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
