// Command seed loads a .sql file into the database of a gqlgate config.
// It connects WITHOUT selecting a schema so the file may create it:
//
//	go run ./example/seed -config example/gqlgate.yaml -file example/seed.sql
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"gqlgate/config"
)

func main() {
	configPath := flag.String("config", "example/gqlgate.yaml", "gqlgate YAML config (for connection settings)")
	file := flag.String("file", "example/seed.sql", "SQL file to execute")
	flag.Parse()

	if err := run(*configPath, *file); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func run(configPath, file string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	d := cfg.Database
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?parseTime=true&charset=utf8mb4&multiStatements=false",
		d.User, d.Password, d.Host, d.Port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The seed file DROPs and recreates its schema, so it must never run
	// against a real database by accident. Unless explicitly overridden, only
	// local/demo hosts are allowed (the compose-internal `tidb` service,
	// localhost, or Docker's host gateway).
	if os.Getenv("GQLGATE_SEED_ALLOW_ANY_HOST") != "1" {
		switch d.Host {
		case "tidb", "127.0.0.1", "localhost", "host.docker.internal":
		default:
			return fmt.Errorf("refusing to seed non-local host %q (this drops and recreates the schema); set GQLGATE_SEED_ALLOW_ANY_HOST=1 to override", d.Host)
		}
	}

	// Wait for the database to come up (docker compose starts us alongside it).
	waitUntil := time.Now().Add(90 * time.Second)
	for {
		if err := db.PingContext(ctx); err == nil {
			break
		} else if time.Now().After(waitUntil) {
			return fmt.Errorf("database at %s:%d not reachable: %w", d.Host, d.Port, err)
		} else {
			fmt.Println("seed: waiting for database...")
			time.Sleep(2 * time.Second)
		}
	}

	// Pin one connection so USE statements keep their effect.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Strip -- comment lines first so semicolons inside comments don't split
	// statements. (This stays a *naive* runner: no semicolons in string
	// literals, no DELIMITER support.)
	var sqlLines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		sqlLines = append(sqlLines, line)
	}

	count := 0
	for _, stmt := range strings.Split(strings.Join(sqlLines, "\n"), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("statement %d failed: %w\n%s", count+1, err, stmt)
		}
		count++
	}
	fmt.Printf("executed %d statements from %s\n", count, file)
	return nil
}
