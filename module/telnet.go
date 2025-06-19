package module

import "github.com/dusbot/honeypotz/query"

type Telnet struct {
	Query *query.Query
}

func NewTelnet(q *query.Query) *Telnet {
	return &Telnet{
		Query: q,
	}
}

func (t *Telnet) Init() error {
	return nil
}

func (t *Telnet) Serve(port int) error {
	return nil
}

func (t *Telnet) Shutdown() error {
	return nil
}
