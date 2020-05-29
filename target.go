package main

import (
	"time"
)

type targets []*target

func (ts targets) findByID(id int) *target {
	for _, t := range ts {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (ts targets) accessibleBy(roles []string) targets {
	targets := targets{}
	for _, t := range ts {
		if t.isAccessibleBy(roles) {
			targets = append(targets, t)
		}
	}
	return targets
}

type target struct {
	ID       int    `json:"id"   yaml:"id"`
	Name     string `json:"name" yaml:"name"`
	Endpoint string `json:"-"    yaml:"endpoint"`
	Proxy    struct {
		Endpoint string `json:"endpoint" yaml:"endpoint"`
	} `json:"proxy" yaml:"proxy"`
	Roles       []string      `json:"-"         yaml:"roles"`
	IdleTimeout time.Duration `json:"-"         yaml:"idleTimeout"`
	SessionTTL  time.Duration `json:"-"         yaml:"sessionTTL"`
	TokenTTL    time.Duration `json:"-"         yaml:"tokenTTL"`
	TokensURL   string        `json:"tokensUrl" yaml:"-"`
}

func (t *target) isAccessibleBy(roles []string) bool {
	for _, r1 := range roles {
		for _, r2 := range t.Roles {
			if r1 == r2 {
				return true
			}
		}
	}
	return false
}
