package common_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unsafe"

	iface "certification_server/src/iface/common"
	modelsystem "certification_server/src/models/system"
	"certification_server/src/repo"
	commonservice "certification_server/src/services/common"
	"certification_server/src/utils"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type credentialTestState struct {
	mu       sync.Mutex
	row      map[string]driver.Value
	err      error
	lastSQL  string
	lastArgs []driver.Value
}

var credentialTestDBState = &credentialTestState{}
var credentialDriverOnce sync.Once

func registerCredentialTestDriver() {
	credentialDriverOnce.Do(func() {
		sql.Register("credential_test_mysql", credentialTestDriver{})
	})
}

type credentialTestDriver struct{}

func (credentialTestDriver) Open(string) (driver.Conn, error) {
	return &credentialTestConn{}, nil
}

type credentialTestConn struct{}

func (c *credentialTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepare not supported")
}

func (c *credentialTestConn) Close() error { return nil }

func (c *credentialTestConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("tx not supported")
}

func (c *credentialTestConn) QueryContext(
	ctx context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Rows, error) {
	_ = ctx
	credentialTestDBState.mu.Lock()
	defer credentialTestDBState.mu.Unlock()
	credentialTestDBState.lastSQL = query
	credentialTestDBState.lastArgs = credentialTestDBState.lastArgs[:0]
	for _, arg := range args {
		credentialTestDBState.lastArgs = append(credentialTestDBState.lastArgs, arg.Value)
	}
	if credentialTestDBState.err != nil {
		return nil, credentialTestDBState.err
	}
	if credentialTestDBState.row == nil {
		return nil, sql.ErrNoRows
	}
	columns := []string{"user_profile_id", "user_name", "role", "password_hash", "hash_algorithm", "status", "metadata"}
	values := make([]driver.Value, len(columns))
	for i, column := range columns {
		values[i] = credentialTestDBState.row[column]
	}
	return &credentialTestRows{columns: columns, values: values}, nil
}

func (c *credentialTestConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (c *credentialTestConn) Ping(context.Context) error { return nil }

type credentialTestRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *credentialTestRows) Columns() []string { return r.columns }

func (r *credentialTestRows) Close() error { return nil }

func (r *credentialTestRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	copy(dest, r.values)
	r.done = true
	return nil
}

func setCredentialTestResult(row map[string]driver.Value, err error) {
	credentialTestDBState.mu.Lock()
	defer credentialTestDBState.mu.Unlock()
	credentialTestDBState.row = row
	credentialTestDBState.err = err
	credentialTestDBState.lastSQL = ""
	credentialTestDBState.lastArgs = nil
}

func lastCredentialSQL() string {
	credentialTestDBState.mu.Lock()
	defer credentialTestDBState.mu.Unlock()
	return credentialTestDBState.lastSQL
}

func newCredentialTestMySQLClient(t *testing.T) *repo.MySQLClient {
	t.Helper()
	registerCredentialTestDriver()
	db, err := sql.Open("credential_test_mysql", "")
	if err != nil {
		t.Fatalf("open fake mysql db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	sqlxDB := sqlx.NewDb(db, "mysql")
	client := &repo.MySQLClient{}
	field := reflect.ValueOf(client).Elem().FieldByName("db")
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(sqlxDB))
	return client
}

func assertSystemErrorString(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q, got nil", want)
	}
	var sysErr *modelsystem.Error
	if !errors.As(err, &sysErr) {
		t.Fatalf("expected system error %q, got %T", want, err)
	}
	if sysErr.Error() != want {
		t.Fatalf("expected %q, got %q", want, sysErr.Error())
	}
}

func TestUserCredentialServiceValidateCredentials(t *testing.T) {
	hashedPassword, err := (&utils.CryptoUtils{}).BcryptHash("secret-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	row := map[string]driver.Value{
		"user_profile_id": uuid.MustParse("11111111-1111-1111-1111-111111111111").String(),
		"user_name":       "alice",
		"role":            "admin",
		"password_hash":   hashedPassword,
		"hash_algorithm":  "bcrypt",
		"status":          "active",
		"metadata":        []byte(`{"risk_rejected":false}`),
	}

	t.Run("success by username", func(t *testing.T) {
		setCredentialTestResult(row, nil)
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		result, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Username: "alice",
			Password: "secret-password",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatalf("expected validation result")
		}
		if result.Principal.EntityID != "alice" {
			t.Fatalf("expected entity id alice, got %q", result.Principal.EntityID)
		}
		if result.UserProfileID.String() != "11111111-1111-1111-1111-111111111111" {
			t.Fatalf("unexpected user profile id: %s", result.UserProfileID)
		}
		if result.Role != "admin" {
			t.Fatalf("expected role admin, got %q", result.Role)
		}
		if got := strings.Join(result.Scopes, ","); got != "user:read,user:write,user:manage" {
			t.Fatalf("unexpected scopes: %s", got)
		}
		if !strings.Contains(lastCredentialSQL(), "user_name") {
			t.Fatalf("expected username lookup query, got %q", lastCredentialSQL())
		}
	})

	t.Run("success by email", func(t *testing.T) {
		setCredentialTestResult(row, nil)
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Email:    "alice@example.com",
			Password: "secret-password",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(lastCredentialSQL(), "email") {
			t.Fatalf("expected email lookup query, got %q", lastCredentialSQL())
		}
	})

	t.Run("success by phone", func(t *testing.T) {
		setCredentialTestResult(row, nil)
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Phone:    "13800000000",
			Password: "secret-password",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(lastCredentialSQL(), "phone") {
			t.Fatalf("expected phone lookup query, got %q", lastCredentialSQL())
		}
	})

	t.Run("missing mysql", func(t *testing.T) {
		svc := commonservice.NewUserCredentialService(nil)
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Username: "alice",
			Password: "secret-password",
		})
		assertSystemErrorString(t, err, modelsystem.ErrMySQLNotConfigured.Error())
	})

	t.Run("missing principal fields", func(t *testing.T) {
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{})
		assertSystemErrorString(t, err, modelsystem.ErrUsernameRequired.Error())
	})

	t.Run("missing password", func(t *testing.T) {
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{Username: "alice"})
		assertSystemErrorString(t, err, modelsystem.ErrPasswordRequired.Error())
	})

	t.Run("not found", func(t *testing.T) {
		setCredentialTestResult(nil, sql.ErrNoRows)
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Username: "alice",
			Password: "secret-password",
		})
		assertSystemErrorString(t, err, modelsystem.ErrUserNotFound.Error())
	})

	t.Run("invalid password", func(t *testing.T) {
		setCredentialTestResult(row, nil)
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Username: "alice",
			Password: "wrong-password",
		})
		assertSystemErrorString(t, err, modelsystem.ErrInvalidUserCredentials.Error())
	})

	t.Run("disabled status", func(t *testing.T) {
		setCredentialTestResult(func() map[string]driver.Value {
			copyRow := make(map[string]driver.Value, len(row))
			for key, value := range row {
				copyRow[key] = value
			}
			copyRow["status"] = "inactive"
			return copyRow
		}(), nil)
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Username: "alice",
			Password: "secret-password",
		})
		assertSystemErrorString(t, err, modelsystem.ErrUserDisabled.Error())
	})

	t.Run("risk rejected", func(t *testing.T) {
		setCredentialTestResult(func() map[string]driver.Value {
			copyRow := make(map[string]driver.Value, len(row))
			for key, value := range row {
				copyRow[key] = value
			}
			copyRow["metadata"] = []byte(`{"risk_rejected":true}`)
			return copyRow
		}(), nil)
		svc := commonservice.NewUserCredentialService(newCredentialTestMySQLClient(t))
		_, err := svc.ValidateCredentials(context.Background(), iface.UserPwdCredentialRequest{
			Username: "alice",
			Password: "secret-password",
		})
		assertSystemErrorString(t, err, modelsystem.ErrUserRiskRejected.Error())
	})
}
