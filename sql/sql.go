package sql

import (
    "database/sql"
    "errors"
    "fmt"
	"strconv"

    _ "github.com/go-sql-driver/mysql"
)

var (
    NotFoundErr = errors.New("id not found")
    FormatErr   = errors.New("ip/auth format err")
    TypeErr     = errors.New("update key: type err, only:int/string/bool")

    db *sql.DB
)

const tableName = "users"

func Conn(ip, auth string) error {
    if ip == "" || auth == "" {
        return FormatErr
    }

    // auth: root:123456
    // ip: 127.0.0.1:3306
    dsn := fmt.Sprintf(
        "%s@tcp(%s)/userkepdb?charset=utf8mb4&parseTime=True&loc=Local",
        auth,
        ip,
    )

    conn, err := sql.Open("mysql", dsn)
    if err != nil {
        return err
    }

    err = conn.Ping()
    if err != nil {
        return err
    }

    conn.SetMaxOpenConns(20)
    conn.SetMaxIdleConns(10)

    db = conn

    return nil
}

func Search(key, val string) int {
    if db == nil {
        return -1
    }

    query := fmt.Sprintf(
        "SELECT id FROM %s WHERE %s=? LIMIT 1",
        tableName,
        key,
    )

    var id int

    err := db.QueryRow(query, val).Scan(&id)
    if err != nil {
        return -1
    }

    return id
}

func GetByID(key string, id int) string {
    if db == nil || id < 0 {
        return ""
    }

    query := fmt.Sprintf(
        "SELECT %s FROM %s WHERE id=? LIMIT 1",
        key,
        tableName,
    )

    var value interface{}

    err := db.QueryRow(query, id).Scan(&value)
    if err != nil {
        return ""
    }

    switch v := value.(type) {
    case []byte:
        return string(v)

    case string:
        return v

    case int:
        return strconv.Itoa(v)

    case int64:
        return strconv.FormatInt(v, 10)

    case bool:
        return strconv.FormatBool(v)

    case float64:
        return strconv.FormatFloat(v, 'f', -1, 64)

    case nil:
        return ""

    default:
        return fmt.Sprintf("%v", v)
    }
}

func Set(key string, val interface{}, id int) error {
    if db == nil {
        return errors.New("db not connected")
    }

    if id < 0 {
        return NotFoundErr
    }

    query := fmt.Sprintf(
        "UPDATE %s SET %s=? WHERE id=?",
        tableName,
        key,
    )

    switch val.(type) {
    case int:
    case string:
    case bool:
    default:
        return TypeErr
    }

    result, err := db.Exec(query, val, id)
    if err != nil {
        return err
    }

    rows, err := result.RowsAffected()
    if err != nil {
        return err
    }

    if rows == 0 {
        return NotFoundErr
    }

    return nil
}

func New() int {
    if db == nil {
        return -1
    }

    query := fmt.Sprintf(
        "INSERT INTO %s () VALUES ()",
        tableName,
    )

    result, err := db.Exec(query)
    if err != nil {
        return -1
    }

    id, err := result.LastInsertId()
    if err != nil {
        return -1
    }

    return int(id)
}