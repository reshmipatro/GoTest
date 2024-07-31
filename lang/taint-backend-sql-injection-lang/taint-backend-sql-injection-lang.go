package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	_ "github.com/aws/aws-lambda-go/lambda"
	"github.com/go-sql-driver/mysql"
)

var (
	db               *sql.DB
	tx               *sql.Tx
	conn             *sql.Conn
	err              error
	connectionString string
	dbUser           string
	dbPass           string
	dataSource       string
	ctx              context.Context
)

const (
	username = "john"
	password = "cena"
)

type Employee struct {
	EmployeeNo int    `json:"emp_no"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
}

func init() {
	connectionString = os.Getenv("CONN")
	dbUser = os.Getenv("DBUSER")
	dbPass = os.Getenv("DBPASS")
	dataSource = dbUser + ":" + dbPass + "@tcp(" + connectionString + ")/employees"
}

func DeleteHandler(db *sql.DB) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		del := req.URL.Query().Get("del")
		id := req.URL.Query().Get("Id")
		if del == "del" {
			// ruleid: taint-backend-sql-injection-lang
			_, err = db.Exec("DELETE FROM table WHERE Id = " + id)
			if err != nil {
				panic(err)
			}
		}
	}
}

func DeleteHandlerOk(db *sql.DB) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		del := req.URL.Query().Get("del")
		idhtml := req.URL.Query().Get("Id")

		id, _ := strconv.Atoi(idhtml)

		if del == "del" {
			// ok: taint-backend-sql-injection-lang
			_, err = db.Exec("DELETE FROM table WHERE Id = " + strconv.Itoa(id))
			if err != nil {
				panic(err)
			}
		}
	}
}

func SelectHandler(db *sql.DB) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		del := req.URL.Query().Get("del")
		id := req.URL.Query().Get("Id")
		if del == "del" {
			sql := fmt.Sprintf("SELECT * FROM table WHERE Id = %v", id)
			// ruleid: taint-backend-sql-injection-lang
			_, err = db.Exec(sql)
			if err != nil {
				panic(err)
			}
		}
	}
}

func SelectHandlerOk(db *sql.DB) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		del := req.URL.Query().Get("del")
		id := req.URL.Query().Get("Id")

		if del == "del" {
			// ok: taint-backend-sql-injection-lang
			_ = db.QueryRow("SELECT * FROM table WHERE Id = $1", id)

			fmt.Fprintf(w, "Deleted %s", id)
			if err != nil {
				panic(err)
			}
		}
	}
}

func SelectHandlerOk1(db *sql.DB) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		del := req.URL.Query().Get("del")
		id := req.URL.Query().Get("Id")

		if del == "del" {
			// ok: taint-backend-sql-injection-lang
			_ = db.QueryRowContext(ctx, "SELECT * FROM table WHERE Id = $1", id)

			fmt.Fprintf(w, "Deleted %s", id)
			if err != nil {
				panic(err)
			}
		}
	}
}

func handler1(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	searchCriteria := request.Body

	db, err = sql.Open("mysql", dataSource)
	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	// ruleid: taint-backend-sql-injection-lang
	results, err := db.Query("select e.emp_no, e.first_name, e.last_name " +
		"from employees e, departments d, dept_emp de " +
		"where e.last_name LIKE '" + searchCriteria + "%';")

	if err != nil {
		log.Fatal(err)
	}
	defer results.Close()

	// ruleid: taint-backend-sql-injection-lang
	_, err = db.Exec("DELETE FROM table WHERE Id = " + request.QueryStringParameters["Id"])

	// ok: taint-backend-sql-injection-lang
	log.Printf("DELETE FROM table WHERE Id = " + request.QueryStringParameters["Id"])

	idhtml := request.QueryStringParameters["Id"]
	id, _ := strconv.Atoi(idhtml)

	// ok: taint-backend-sql-injection-lang
	_, err = db.Exec("DELETE FROM table WHERE Id = " + strconv.Itoa(id))

	// ok: taint-backend-sql-injection-lang
	db.Query("select * from foobar")

	employees := make([]Employee, 0)

	for results.Next() {
		var e Employee

		err := results.Scan(&e.EmployeeNo, &e.FirstName, &e.LastName)
		if err != nil {
			log.Fatal(err)
		}
		employees = append(employees, e)
	}

	data, _ := json.Marshal(employees)

	return events.APIGatewayProxyResponse{
		StatusCode:      200,
		Body:            string(data),
		IsBase64Encoded: false,
	}, nil
}

func handler2(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	searchCriteria := request.Body

	db, err = sql.Open("mysql", dataSource)
	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	// ruleid: taint-backend-sql-injection-lang
	results, err := db.Query("select e.emp_no, e.first_name, e.last_name " +
		"from employees e, departments d, dept_emp de " +
		"where de.emp_no = e.emp_no " +
		"and de.dept_no = d.dept_no " +
		"and d.dept_name = 'Marketing' " +
		"and e.last_name LIKE '" + searchCriteria + "%';")

	if err != nil {
		log.Fatal(err)
	}
	defer results.Close()

	// ok: taint-backend-sql-injection-lang
	db.Query("select * from foobar")

	employees := make([]Employee, 0)

	for results.Next() {
		var e Employee

		err := results.Scan(&e.EmployeeNo, &e.FirstName, &e.LastName)
		if err != nil {
			log.Fatal(err)
		}
		employees = append(employees, e)
	}

	data, _ := json.Marshal(employees)

	return events.APIGatewayProxyResponse{
		StatusCode:      200,
		Body:            string(data),
		IsBase64Encoded: false,
	}, nil
}

func handler3(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	searchCriteria := request.Body

	_db, err := sql.Open("mysql", dataSource)
	if err != nil {
		panic(err.Error())
	}

	defer _db.Close()

	// ruleid: taint-backend-sql-injection-lang
	results, err := _db.QueryContext(ctx, "select e.emp_no, e.first_name, e.last_name "+
		"from employees e, departments d, dept_emp de "+
		"where e.last_name LIKE '"+searchCriteria+"%';")

	if err != nil {
		log.Fatal(err)
	}
	defer results.Close()

	// ruleid: taint-backend-sql-injection-lang
	_, err = _db.ExecContext(ctx, "DELETE FROM table WHERE Id = "+request.QueryStringParameters["Id"])

	// ok: taint-backend-sql-injection-lang
	log.Printf("DELETE FROM table WHERE Id = " + request.QueryStringParameters["Id"])

	idhtml := request.QueryStringParameters["Id"]
	id, _ := strconv.Atoi(idhtml)

	// ok: taint-backend-sql-injection-lang
	_, err = _db.ExecContext(ctx, "DELETE FROM table WHERE Id = "+strconv.Itoa(id))

	// ok: taint-backend-sql-injection-lang
	_db.QueryContext(ctx, "select * from foobar")

	employees := make([]Employee, 0)

	for results.Next() {
		var e Employee

		err := results.Scan(&e.EmployeeNo, &e.FirstName, &e.LastName)
		if err != nil {
			log.Fatal(err)
		}
		employees = append(employees, e)
	}

	data, _ := json.Marshal(employees)

	return events.APIGatewayProxyResponse{
		StatusCode:      200,
		Body:            string(data),
		IsBase64Encoded: false,
	}, nil
}

type MyEvent struct {
	Smth string
}

func HandleRequest(ctx context.Context, name MyEvent) (events.APIGatewayProxyResponse, error) {
	// Assume this is alright for now
	// TODO: Make sure this is actually alright
	searchCriteria := ctx.Value("Smth").(string)

	db, err = sql.Open("mysql", dataSource)
	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	// ok: taint-backend-sql-injection-lang
	results, err := db.Query("select e.emp_no, e.first_name, e.last_name " +
		"from employees e, departments d, dept_emp de " +
		"where de.emp_no = e.emp_no " +
		"and de.dept_no = d.dept_no " +
		"and d.dept_name = 'Marketing' " +
		"and e.last_name LIKE '" + searchCriteria + "%';")

	if err != nil {
		log.Fatal(err)
	}
	defer results.Close()

	data, _ := json.Marshal(results)

	return events.APIGatewayProxyResponse{
		StatusCode:      200,
		Body:            string(data),
		IsBase64Encoded: false,
	}, nil
}

func bad01(w http.ResponseWriter, req *http.Request) {
	_tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_tx.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_tx.QueryContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_tx.QueryRowContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_tx.PrepareContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_tx.Exec("DELETE FROM table WHERE Id = " + id)
	// ruleid: taint-backend-sql-injection-lang
	_tx.Query("DELETE FROM table WHERE Id = " + id)
	// ruleid: taint-backend-sql-injection-lang
	_tx.QueryRow("DELETE FROM table WHERE Id = " + id)
	// ruleid: taint-backend-sql-injection-lang
	_tx.Prepare("DELETE FROM table WHERE Id = " + id)
}

func bad02(w http.ResponseWriter, req *http.Request) {
	_tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_tx.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad03(w http.ResponseWriter, req *http.Request) {
	_db, _ := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/hello")
	_tx, err := _db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_tx.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad04(w http.ResponseWriter, req *http.Request) {
	_db, _ := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/hello")
	_tx, err := _db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_tx.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad05(w http.ResponseWriter, req *http.Request) {
	// Specify connection properties.
	cfg := mysql.Config{
		User:   username,
		Passwd: password,
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "jazzrecords",
	}

	// Get a driver-specific connector.
	connector, err := mysql.NewConnector(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Get a database handle.
	_db := sql.OpenDB(connector)
	_tx, err := _db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_tx.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad06(w http.ResponseWriter, req *http.Request) {
	// Specify connection properties.
	cfg := mysql.Config{
		User:   username,
		Passwd: password,
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "jazzrecords",
	}

	// Get a driver-specific connector.
	connector, err := mysql.NewConnector(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Get a database handle.
	_db := sql.OpenDB(connector)
	_tx, err := _db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_tx.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad07(w http.ResponseWriter, req *http.Request) {
	_tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_tx.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad08(w http.ResponseWriter, req *http.Request) {
	localConn, err := db.Conn(ctx)
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	localConn.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	localConn.QueryContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	localConn.QueryRowContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad09(w http.ResponseWriter, req *http.Request) {
	_db, _ := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/hello")
	localConn, err := _db.Conn(ctx)
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	localConn.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	localConn.QueryContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	localConn.QueryRowContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad11(w http.ResponseWriter, req *http.Request) {
	// Specify connection properties.
	cfg := mysql.Config{
		User:   username,
		Passwd: password,
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "jazzrecords",
	}

	// Get a driver-specific connector.
	connector, err := mysql.NewConnector(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Get a database handle.
	_db := sql.OpenDB(connector)
	_, err = _db.Conn(ctx)
	if err != nil {
		log.Fatal(err)
	}
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_, err = conn.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_, err = conn.QueryContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_ = conn.QueryRowContext(ctx, "DELETE FROM table WHERE Id = "+id)
}

func bad12(w http.ResponseWriter, req *http.Request) {
	id := req.FormValue("id")
	// ruleid: taint-backend-sql-injection-lang
	_, err = conn.ExecContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_, err = conn.QueryContext(ctx, "DELETE FROM table WHERE Id = "+id)
	// ruleid: taint-backend-sql-injection-lang
	_ = conn.QueryRowContext(ctx, "DELETE FROM table WHERE Id = "+id)
}
