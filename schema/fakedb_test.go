package schema

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
)

// fakeDB is a database/sql handle whose every query is answered by a Go
// function, for testing the startup checks without TiDB. The function returns
// the result columns and rows, or an error.
type fakeAnswer func(query string) ([]string, [][]driver.Value, error)

func newFakeDB(answer fakeAnswer) (*sql.DB, *fakeLog) {
	log := &fakeLog{}
	return sql.OpenDB(&fakeConnector{answer: answer, log: log}), log
}

// fakeLog records the queries a fakeDB saw.
type fakeLog struct {
	mu      sync.Mutex
	queries []string
}

func (l *fakeLog) add(q string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queries = append(l.queries, q)
}

func (l *fakeLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.queries...)
}

type fakeConnector struct {
	answer fakeAnswer
	log    *fakeLog
}

func (c *fakeConnector) Connect(context.Context) (driver.Conn, error) { return &fakeConn{c}, nil }
func (c *fakeConnector) Driver() driver.Driver                        { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("fakeDriver: use the connector")
}

type fakeConn struct{ c *fakeConnector }

func (c *fakeConn) Prepare(q string) (driver.Stmt, error) { return &fakeStmt{c: c.c, q: q}, nil }
func (c *fakeConn) Close() error                          { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)             { return nil, errors.New("fakeConn: no transactions") }

func (c *fakeConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.c.query(q)
}

func (c *fakeConnector) query(q string) (driver.Rows, error) {
	c.log.add(q)
	cols, rows, err := c.answer(q)
	if err != nil {
		return nil, err
	}
	return &fakeRows{cols: cols, rows: rows}, nil
}

type fakeStmt struct {
	c *fakeConnector
	q string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }
func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("fakeStmt: no exec")
}
func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error) { return s.c.query(s.q) }

type fakeRows struct {
	cols []string
	rows [][]driver.Value
	i    int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}
