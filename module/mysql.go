package module

import "github.com/dusbot/honeypotz/query"

type Mysql struct {
	Query *query.Query
}

func NewMysql(q *query.Query) *Mysql {
	return &Mysql{
		Query: q,
	}
}

func (m *Mysql) Init() error {
	return nil
}

func (m *Mysql) Serve(port int) error {
	return nil
}

func (m *Mysql) Shutdown() error {
	return nil
}
