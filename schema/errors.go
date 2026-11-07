package schema

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
)

// Error codes carried in a GraphQL error's extensions.code. They classify
// what went wrong so clients can react (show a "name taken" message, retry a
// conflict) without parsing messages.
const (
	CodeConstraintViolation = "constraint_violation"  // duplicate value for a unique key
	CodeForeignKeyViolation = "foreign_key_violation" // missing parent / row still referenced
	CodeNotNullViolation    = "not_null_violation"    // required column left null
	CodeDataTooLong         = "data_too_long"         // value longer than the column
	CodeDataException       = "data_exception"        // value out of range / invalid for the column
	CodeCheckViolation      = "check_violation"       // a table CHECK constraint failed
	CodeConflict            = "conflict"              // lock wait, deadlock or write conflict: retry
	CodeTimeout             = "timeout"               // the request ran out of time
	CodeDatabaseError       = "database_error"        // anything else the database reported
	CodePermissionError     = "permission_error"      // a role's insert/update check failed
	CodeResponseTooLarge    = "response_too_large"    // server.max_response_rows/bytes exceeded
	CodeJSONShapeMismatch   = "json_shape_mismatch"   // stored JSON does not fit its declared json_type
)

// CodedError is an error with a machine-readable code. graphql-go copies
// Extensions() into the error's "extensions" member of the response.
type CodedError struct {
	Message string
	Code    string
	// DBNumber is the MySQL/TiDB error number; reported only in debug mode.
	DBNumber uint16
}

func (e *CodedError) Error() string { return e.Message }

// Extensions implements gqlerrors.ExtendedError.
func (e *CodedError) Extensions() map[string]any {
	ext := map[string]any{"code": e.Code}
	if e.DBNumber != 0 {
		ext["db_error_number"] = int(e.DBNumber)
	}
	return ext
}

// dbErrorClass maps MySQL/TiDB error numbers to a code and a client-safe
// message. The raw database message is never used here: it can carry SQL,
// key names and values of columns the role cannot read (a duplicate-key
// message quotes the conflicting value).
var dbErrorClass = map[uint16]struct{ code, msg string }{
	1062: {CodeConstraintViolation, "unique constraint violated: a row with the same key already exists"},
	1586: {CodeConstraintViolation, "unique constraint violated: a row with the same key already exists"},
	1451: {CodeForeignKeyViolation, "foreign key violation: the row is still referenced by other rows"},
	1452: {CodeForeignKeyViolation, "foreign key violation: the referenced row does not exist"},
	1048: {CodeNotNullViolation, "not-null violation: a required column was set to null"},
	1364: {CodeNotNullViolation, "not-null violation: a required column has no value and no default"},
	1406: {CodeDataTooLong, "value too long for its column"},
	1264: {CodeDataException, "value out of range for its column"},
	1690: {CodeDataException, "value out of range"},
	1265: {CodeDataException, "value truncated for its column"},
	1292: {CodeDataException, "invalid value for its column"},
	1366: {CodeDataException, "invalid value for its column"},
	3819: {CodeCheckViolation, "check constraint violated"},
	1205: {CodeConflict, "lock wait timeout: the rows are locked by another transaction; retry the request"},
	1213: {CodeConflict, "deadlock with a concurrent transaction; retry the request"},
	8002: {CodeConflict, "write conflict with a concurrent transaction; retry the request"},
	8022: {CodeConflict, "write conflict with a concurrent transaction; retry the request"},
	8028: {CodeConflict, "the table definition changed during the transaction; retry the request"},
	9007: {CodeConflict, "write conflict with a concurrent transaction; retry the request"},
}

const genericDBMessage = "database error (enable server.debug to see details)"

// classifyDBError returns the code and client-safe message for a database
// error, plus the server's error number when there is one.
func classifyDBError(err error) (code, msg string, number uint16) {
	if errors.Is(err, context.DeadlineExceeded) {
		return CodeTimeout, "the request timed out (database.query_timeout_seconds)", 0
	}
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		if c, ok := dbErrorClass[me.Number]; ok {
			return c.code, c.msg, me.Number
		}
		return CodeDatabaseError, genericDBMessage, me.Number
	}
	return CodeDatabaseError, genericDBMessage, 0
}

// dbErr turns a database error into a client-facing coded error. Expected,
// user-caused errors (duplicate key, foreign key, not null, too long, check
// constraint, conflicts) get their code and a safe message; anything else is
// masked. With server.debug the database's own message is passed through.
func (b *builder) dbErr(err error) error {
	if err == nil {
		return nil
	}
	if err == sql.ErrNoRows {
		return err
	}
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce // already classified (e.g. a response limit hit while scanning)
	}
	code, msg, number := classifyDBError(err)
	if b.opt.Config.Server.Debug {
		return &CodedError{Message: err.Error(), Code: code, DBNumber: number}
	}
	if b.opt.Logger != nil {
		if code == CodeDatabaseError {
			b.opt.Logger.Error("database error", "role", b.role, "err", err)
		} else {
			b.opt.Logger.Info("database rejected the request", "role", b.role, "code", code, "err", err)
		}
	}
	return &CodedError{Message: msg, Code: code}
}

// checkFailed is the error of a write whose rows do not satisfy the role's
// insert/update check. The mutation has been rolled back.
func checkFailed(op, table string) error {
	return &CodedError{
		Code:    CodePermissionError,
		Message: fmt.Sprintf("permission check failed: a row written by this %s on %q does not satisfy the role's %s check; nothing was written", op, table, op),
	}
}

// checkUnverifiable is the error of a write whose rows could not all be found
// again by their key (the database stored a key in another form than the one
// sent, or changed it), so the role's check cannot be verified. It fails
// closed: the mutation has been rolled back.
func checkUnverifiable(op, table string) error {
	return &CodedError{
		Code: CodePermissionError,
		Message: fmt.Sprintf("permission check failed: the rows written by this %s on %q could not be found again by their key "+
			"to verify the role's %s check; nothing was written (send key values in the form the column stores them)", op, table, op),
	}
}
