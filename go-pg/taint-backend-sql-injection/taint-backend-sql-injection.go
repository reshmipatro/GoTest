package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-pg/pg/v10"
)

type Book struct {
	name string
}

var (
	_db              *pg.DB
	err              error
	connectionString string
	dbUser           string
	dbPass           string
	dataSource       string
)

func init() {
	_db = pg.Connect(&pg.Options{
		Addr:     ":5432",
		User:     "user",
		Password: "pass",
		Database: "db_name",
	})
}

func getTLSConfig() *tls.Config {
	pgSSLMode := os.Getenv("PGSSLMODE")
	if pgSSLMode == "disable" {
		return nil
	}
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func pgOptions() *pg.Options {
	return &pg.Options{
		User:               dbUser,
		Password:           dbPass,
		TLSConfig:          getTLSConfig(),
		MaxRetries:         1,
		MinRetryBackoff:    -1,
		DialTimeout:        30 * time.Second,
		ReadTimeout:        10 * time.Second,
		WriteTimeout:       10 * time.Second,
		PoolSize:           10,
		MaxConnAge:         10 * time.Second,
		PoolTimeout:        30 * time.Second,
		IdleTimeout:        10 * time.Second,
		IdleCheckFrequency: 100 * time.Millisecond,
	}
}

func bad1(w http.ResponseWriter, req *http.Request) {
	db := pg.Connect(&pg.Options{
		Addr:     ":5432",
		User:     "user",
		Password: "pass",
		Database: "db_name",
	})
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")
	book := new(Book)
	db.Model(book).
		Where("id > ?", 100).
		// ruleid: taint-backend-sql-injection
		WhereOr(query).
		Limit(1).
		Select()
}

func bad2(w http.ResponseWriter, req *http.Request) {
	db := pg.Connect(pgOptions())
	book := new(Book)
	err = db.Model(book).
		Relation("Author").
		// ruleid: taint-backend-sql-injection
		Where("SELECT name FROM users WHERE age=" + req.FormValue("age")).
		Select()
	if err != nil {
		panic(err)
	}
}

func bad3(w http.ResponseWriter, req *http.Request) {
	opt, err := pg.ParseURL("postgres://user:pass@localhost:5432/db_name")
	if err != nil {
		panic(err)
	}

	db := pg.Connect(opt)

	query := "SELECT name FROM users WHERE age="
	query += req.FormValue("age")
	book := new(Book)
	db.Model(book).
		// ruleid: taint-backend-sql-injection
		Where(query).
		WhereGroup(func(q *pg.Query) (*pg.Query, error) {
			q = q.WhereOr("id = 1").
				WhereOr("id = 2")
			return q, nil
		}).
		Limit(1).
		Select()
}

func bad4(db *pg.DB, req *http.Request) {
	email := req.FormValue("email")
	query := fmt.Sprintf("SELECT * FROM users WHERE email='%s';", email)
	db.Model((*Book)(nil)).
		Column("author_id").
		// ruleid: taint-backend-sql-injection
		ColumnExpr(query).
		Group("author_id").
		Order("book_count DESC").
		Select()
}

func bad5(db *pg.Conn, req *http.Request) {
	err = db.Model((*Book)(nil)).
		Column("title", "text").
		// ruleid: taint-backend-sql-injection
		Where("SELECT name FROM users WHERE age=" + req.FormValue("age")).
		Select()
}

func bad6(db *pg.Conn, w http.ResponseWriter, req *http.Request) {
	email := req.FormValue("email")
	err = db.Model((*Book)(nil)).
		Column("title", "text").
		// ruleid: taint-backend-sql-injection
		Where(fmt.Sprintf("SELECT * FROM users WHERE email='%s';", email)).
		Select()
}

func bad7(w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")
	book := new(Book)
	_db.Model(book).
		Where("id > ?", 100).
		// ruleid: taint-backend-sql-injection
		WhereOr(query).
		Limit(1).
		Select()
}

func bad8(w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")
	// ruleid: taint-backend-sql-injection
	_db.Prepare(query)
}

func bad9(w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")
	conn := _db.Conn()
	defer conn.Close()

	// ruleid: taint-backend-sql-injection
	conn.Exec(query)
}

func bad10(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")
	// ruleid: taint-backend-sql-injection
	db.ExecOne(query)
}

func bad11(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")

	var books []Book
	// ruleid: taint-backend-sql-injection
	db.Query(&books, query)
}

func bad12(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")

	var book Book
	// ruleid: taint-backend-sql-injection
	db.QueryOne(&book, query)
}

func bad13(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + req.FormValue("age")

	var book Book
	// ruleid: taint-backend-sql-injection
	db.QueryOne(&book, query)
}

func ok1(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := fmt.Sprintf("SELECT * FROM users WHERE email=hello;")
	err = db.Model((*Book)(nil)).
		Column("title", "text").
		// ok: taint-backend-sql-injection
		Where(query).
		Select()
}

func ok2(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=" + "3"
	err = db.Model((*Book)(nil)).
		Column("title", "text").
		// ok: taint-backend-sql-injection
		ColumnExpr(query).
		Select()
}

func ok3(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age="
	query += "3"
	err = db.Model((*Book)(nil)).
		Column("title", "text").
		// ok: taint-backend-sql-injection
		Where(query).
		Select()
}

func ok4(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	var title string
	var text string
	db.Model((*Book)(nil)).
		Column("title", "text").
		// ok: taint-backend-sql-injection
		Where("id = ?", 1).
		Select(&title, &text)
}

func ok5(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	var title, text string
	db.Model((*Book)(nil)).
		Column("title", "text").
		// ok: taint-backend-sql-injection
		Where("SELECT name FROM users WHERE age="+"3").
		Select(&title, &text)
}

func ok6(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-sql-injection
	db.Model().
		ColumnExpr(fmt.Sprintf("SELECT * FROM users WHERE email=hello;"))
}

func ok7(w http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-sql-injection
	path.Join("foo", fmt.Sprintf("%s.baz", "bar"))
}

func ok8(w http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-sql-injection
	filepath.Join("foo", fmt.Sprintf("%s.baz", "bar"))
}

func ok9(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	id, _ := strconv.Atoi(req.FormValue("id"))
	db.Model().
		// ok: taint-backend-sql-injection
		ColumnExpr(fmt.Sprintf("SELECT * FROM users WHERE id = %v", id))
}

func ok10(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=?"
	// ok: taint-backend-sql-injection
	db.ExecOne(query, req.FormValue("age"))
}

func ok11(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=?"

	var books []Book
	// ok: taint-backend-sql-injection
	db.Query(&books, query, req.FormValue("age"))
}

func ok12(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=?"

	var book Book
	// ok: taint-backend-sql-injection
	db.QueryOne(&book, query, req.FormValue("age"))
}

func ok13(db *pg.DB, w http.ResponseWriter, req *http.Request) {
	query := "SELECT name FROM users WHERE age=?"

	var book Book
	// ok: taint-backend-sql-injection
	db.QueryOne(&book, query, req.FormValue("age"))
}
