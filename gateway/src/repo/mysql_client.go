package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gateway/src/models"
	"gateway/src/utils"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// MySQLClient 提供面向原生 SQL 和动态结果的 MySQL 基础客户端。
type MySQLClient struct {
	db        *sqlx.DB
	breaker   *utils.CircuitBreaker
	opTimeout time.Duration
	dsn       string
}

// NewMySQLClient 创建并探活连接到第一个可用的 MySQL 实例。
func NewMySQLClient(cfg *models.MySQLConfig) (*MySQLClient, error) {
	if cfg == nil {
		return nil, &models.ErrMySQLConfigNeeded
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = 3 * time.Second
	}

	dsns := make([]string, 0)
	for _, dsn := range cfg.DSNs {
		if dsn != "" {
			dsns = append(dsns, dsn)
		}
	}
	if cfg.DSN != "" {
		dsns = append(dsns, cfg.DSN)
	}
	
	if len(dsns) == 0 {
		return nil, &models.ErrMySQLDSNRequired
	}

	var lastErr error
	for _, dsn := range dsns {
		db, err := sqlx.Open("mysql", dsn)
		if err != nil {
			lastErr = err
			continue
		}
		applyMySQLPoolConfig(db, cfg)

		ctx, cancel := context.WithTimeout(context.Background(), cfg.OpTimeout)
		pingErr := db.PingContext(ctx)
		cancel()
		if pingErr != nil {
			_ = db.Close()
			lastErr = pingErr
			continue
		}

		return &MySQLClient{
			db:        db,
			breaker:   utils.NewCircuitBreaker("mysql-client", cfg.CircuitBreaker),
			opTimeout: cfg.OpTimeout,
			dsn:       dsn,
		}, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", &models.ErrMySQLNoAvailable, lastErr)
	}
	return nil, &models.ErrMySQLNoAvailable
}

// Raw 返回底层 sqlx DB。
func (c *MySQLClient) Raw() *sqlx.DB {
	if c == nil {
		return nil
	}
	return c.db
}

// DSN 返回当前已连接的连接串。
func (c *MySQLClient) DSN() string {
	if c == nil {
		return ""
	}
	return c.dsn
}

// Close 关闭连接池。
func (c *MySQLClient) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Ping 检查数据库连接状态。
func (c *MySQLClient) Ping(ctx context.Context) error {
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return nil, c.db.PingContext(execCtx)
	})
	return err
}

// Exec 执行写操作 SQL。
func (c *MySQLClient) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return c.db.ExecContext(execCtx, query, args...)
	})
	if err != nil {
		return nil, err
	}
	return res.(sql.Result), nil
}

// NamedExec 执行命名参数写操作。
func (c *MySQLClient) NamedExec(ctx context.Context, query string, arg any) (sql.Result, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return c.db.NamedExecContext(execCtx, query, arg)
	})
	if err != nil {
		return nil, err
	}
	return res.(sql.Result), nil
}

// Get 扫描单条结果到 dest。
func (c *MySQLClient) Get(ctx context.Context, dest any, query string, args ...any) error {
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return nil, c.db.GetContext(execCtx, dest, query, args...)
	})
	return err
}

// Select 扫描多条结果到 dest。
func (c *MySQLClient) Select(ctx context.Context, dest any, query string, args ...any) error {
	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return nil, c.db.SelectContext(execCtx, dest, query, args...)
	})
	return err
}

// QueryMap 查询单条 map 结果，未命中时返回 nil, nil。
func (c *MySQLClient) QueryMap(ctx context.Context, query string, args ...any) (map[string]any, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		rows, queryErr := c.db.QueryxContext(execCtx, query, args...)
		if queryErr != nil {
			return nil, queryErr
		}
		defer rows.Close()

		if !rows.Next() {
			if rows.Err() != nil {
				return nil, rows.Err()
			}
			return nil, nil
		}

		item := map[string]any{}
		if scanErr := rows.MapScan(item); scanErr != nil {
			return nil, scanErr
		}
		return item, nil
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.(map[string]any), nil
}

// QueryMaps 查询多条 map 结果。
func (c *MySQLClient) QueryMaps(ctx context.Context, query string, args ...any) ([]map[string]any, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		rows, queryErr := c.db.QueryxContext(execCtx, query, args...)
		if queryErr != nil {
			return nil, queryErr
		}
		defer rows.Close()

		items := make([]map[string]any, 0)
		for rows.Next() {
			item := map[string]any{}
			if scanErr := rows.MapScan(item); scanErr != nil {
				return nil, scanErr
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			return nil, rows.Err()
		}
		return items, nil
	})
	if err != nil {
		return nil, err
	}
	return res.([]map[string]any), nil
}

// BeginTx 创建事务。
func (c *MySQLClient) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sqlx.Tx, error) {
	res, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		return c.db.BeginTxx(execCtx, opts)
	})
	if err != nil {
		return nil, err
	}
	return res.(*sqlx.Tx), nil
}

// WithTx 在事务中执行回调，成功提交，失败回滚。
func (c *MySQLClient) WithTx(ctx context.Context, opts *sql.TxOptions, fn func(*sqlx.Tx) error) error {
	if fn == nil {
		return &models.ErrTxFuncNil
	}

	_, err := c.execute(ctx, func(execCtx context.Context) (any, error) {
		tx, beginErr := c.db.BeginTxx(execCtx, opts)
		if beginErr != nil {
			return nil, beginErr
		}

		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()

		if runErr := fn(tx); runErr != nil {
			return nil, runErr
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return nil, commitErr
		}
		committed = true
		return nil, nil
	})
	return err
}

// GetAs 将单条结果扫描为具体类型。
func GetAs[T any](ctx context.Context, client *MySQLClient, query string, args ...any) (T, error) {
	var dest T
	if client == nil {
		return dest, &models.ErrNilMySQLClient
	}
	err := client.Get(ctx, &dest, query, args...)
	return dest, err
}

// SelectAs 将多条结果扫描为具体类型切片。
func SelectAs[T any](ctx context.Context, client *MySQLClient, query string, args ...any) ([]T, error) {
	items := make([]T, 0)
	if client == nil {
		return nil, &models.ErrNilMySQLClient
	}
	err := client.Select(ctx, &items, query, args...)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (c *MySQLClient) execute(ctx context.Context, fn func(context.Context) (any, error)) (any, error) {
	if c == nil || c.db == nil {
		return nil, &models.ErrNilMySQLClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	if c.breaker != nil {
		return c.breaker.CallWithResult(ctx, fn)
	}
	return fn(ctx)
}

func (c *MySQLClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c == nil || c.opTimeout <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.opTimeout)
}

func applyMySQLPoolConfig(db *sqlx.DB, cfg *models.MySQLConfig) {
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}
}

// IsNotFound 判断错误是否为 sql.ErrNoRows。
func IsNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
