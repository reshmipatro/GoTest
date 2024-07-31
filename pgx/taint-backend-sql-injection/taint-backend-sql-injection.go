package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5"
)

func bad1(w http.ResponseWriter, req *http.Request) {
	config, _ := pgx.ParseConfig("host=localhost port=3363 user=test password=password database=benchmark_db")
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal(err)
	}
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")
	// ruleid: taint-backend-sql-injection
	conn.Query(context.Background(), query)
}

func bad2(w http.ResponseWriter, req *http.Request) {
	conn, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")
	// ruleid: taint-backend-sql-injection
	conn.Query(context.Background(), query)
}

func bad3(w http.ResponseWriter, req *http.Request) {
	config, err := pgx.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}

	conn, _ := pgx.ConnectConfig(context.Background(), config)

	query := "SELECT name FROM users WHERE age="
	query += req.FormValue("age")
	// ruleid: taint-backend-sql-injection
	conn.QueryRow(context.Background(), query)
}

func bad4(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	email := req.FormValue("email")
	query := fmt.Sprintf("SELECT * FROM users WHERE email='%s';", email)
	// ruleid: taint-backend-sql-injection
	conn.Exec(context.Background(), query)
}

func bad5(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	// ruleid: taint-backend-sql-injection
	conn.Exec(context.Background(), "SELECT name FROM users WHERE age="+req.FormValue("age"))
}

func bad6(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	email := req.FormValue("email")
	// ruleid: taint-backend-sql-injection
	conn.Exec(context.Background(), fmt.Sprintf("SELECT * FROM users WHERE email='%s';", email))
}

func ok1(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	query := fmt.Sprintf("SELECT * FROM users WHERE email=hello;")
	// ok: taint-backend-sql-injection
	conn.QueryRow(context.Background(), query)
}

func ok2(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + "3"
	// ok: taint-backend-sql-injection
	conn.Query(context.Background(), query)
}

func ok3(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age="
	query += "3"
	// ok: taint-backend-sql-injection
	conn.QueryRow(context.Background(), query)
}

func ok4(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-sql-injection
	conn.Exec(context.Background(), "INSERT INTO users(name, email) VALUES($1, $2)",
		"Jon Calhoun", "jon@calhoun.io")
}

func ok5(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-sql-injection
	conn.Exec(context.Background(), "SELECT name FROM users WHERE age="+"3")
}

func ok6(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-sql-injection
	conn.Exec(context.Background(), fmt.Sprintf("SELECT * FROM users WHERE email=hello;"))
}

func ok7(w http.ResponseWriter, req *http.Request) {
	config, _ := pgx.ParseConfig("host=localhost port=3363 user=test password=password database=benchmark_db")
	db, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		panic(err)
	}
	if _, err := db.Prepare(context.Background(), "my-query", "select $1::int"); err != nil {
		panic(err)
	}
	// ok: taint-backend-sql-injection
	row := db.QueryRow(context.Background(), "my-query", 10)
	var i int
	if err := row.Scan(&i); err != nil {
		panic(err)
	}
	fmt.Println(i)
}

func ok8(conn *pgx.Conn, w http.ResponseWriter, req *http.Request) {
	id, _ := strconv.Atoi(req.FormValue("id"))
	// ok: taint-backend-sql-injection
	conn.Exec(context.Background(), fmt.Sprintf("SELECT * FROM users WHERE id='%d';", id))
}
