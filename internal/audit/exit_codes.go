package audit

// Exit codes as per spec 7.2
const (
	ExitSuccess          = 0 // success (including idempotent no-op)
	ExitValidationError  = 2 // validation error (bad name/type/ttl/rdata)
	ExitPreconditionFail = 3 // precondition failure (BIND/rndc/config missing)
	ExitRuntimeFailure   = 4 // runtime failure (rndc failure, update refused, IO error)
	ExitConflictUnsafe   = 5 // conflict/unsafe (policy violation, ambiguous catalog label)
	ExitInternalError    = 6 // internal error
)
