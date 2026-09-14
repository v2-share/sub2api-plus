package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	dbent "github.com/LuckyKuang/sub2api-plus/ent"
	_ "github.com/LuckyKuang/sub2api-plus/ent/runtime"
	"github.com/LuckyKuang/sub2api-plus/internal/service"
	"github.com/stretchr/testify/require"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
)

func TestBulkUpdateExplicitCodexFingerprintModeMergesValue(t *testing.T) {
	exec := &recordingSQLExecutor{result: rowsAffectedResult(1)}
	repo := newAccountRepositoryWithSQL(nil, exec, nil)

	_, err := repo.BulkUpdate(context.Background(), []int64{27}, service.AccountBulkUpdate{
		Extra: map[string]any{service.CodexFingerprintModeExtraKey: "device"},
	})

	require.NoError(t, err)
	require.NotEmpty(t, exec.execQueries)
	query := normalizeSQLWhitespace(exec.execQueries[0])
	require.Contains(t, query, "jsonb_set(COALESCE(extra, '{}'::jsonb) || $1::jsonb, '{codex_fingerprint_seed}'")
	require.Contains(t, query, "gen_random_uuid()", "开启收敛的批量更新必须原子保证种子存在")
	require.NotContains(t, query, "- 'codex_fingerprint_mode'")
	payload, ok := exec.execArgs[0][0].([]byte)
	require.True(t, ok)
	require.JSONEq(t, `{"codex_fingerprint_mode":"device"}`, string(payload))
}

func TestBulkUpdateCodexFingerprintModeOffDoesNotEnsureSeed(t *testing.T) {
	exec := &recordingSQLExecutor{result: rowsAffectedResult(1)}
	repo := newAccountRepositoryWithSQL(nil, exec, nil)

	_, err := repo.BulkUpdate(context.Background(), []int64{27}, service.AccountBulkUpdate{
		Extra: map[string]any{service.CodexFingerprintModeExtraKey: "off"},
	})

	require.NoError(t, err)
	query := normalizeSQLWhitespace(exec.execQueries[0])
	require.Contains(t, query, "extra = COALESCE(extra, '{}'::jsonb) || $1::jsonb")
	require.NotContains(t, query, "codex_fingerprint_seed", "off 更新不得触发种子保证写放大")
}

// UpdateExtra 开启收敛时必须走 SQL 层原子种子保证 (jsonb_set + gen_random_uuid),
// 并在同一事务内落库后提交。
func TestUpdateExtraEnablingCodexFingerprintConvergenceEnsuresSeed(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	driver := entsql.OpenDB(dialect.Postgres, db)
	client := dbent.NewClient(dbent.Driver(driver))
	t.Cleanup(func() { _ = client.Close() })
	repo := newAccountRepositoryWithSQL(client, db, nil)

	mock.ExpectBegin()
	mock.ExpectExec("jsonb_set").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO scheduler_outbox").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, repo.UpdateExtra(context.Background(), 27, map[string]any{
		service.CodexFingerprintModeExtraKey: "device",
	}))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateExtraCodexFingerprintModeOffDoesNotEnsureSeed(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	driver := entsql.OpenDB(dialect.Postgres, db)
	client := dbent.NewClient(dbent.Driver(driver))
	t.Cleanup(func() { _ = client.Close() })
	repo := newAccountRepositoryWithSQL(client, db, nil)

	mock.ExpectBegin()
	mock.ExpectExec("\\$1::jsonb, updated_at").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO scheduler_outbox").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, repo.UpdateExtra(context.Background(), 27, map[string]any{
		service.CodexFingerprintModeExtraKey: "off",
	}))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCodexFingerprintModeExtraUpdateIsSchedulerRelevant(t *testing.T) {
	require.True(t, shouldEnqueueSchedulerOutboxForExtraUpdates(map[string]any{
		service.CodexFingerprintModeExtraKey: "device",
	}))
}
