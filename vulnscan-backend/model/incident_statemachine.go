package model

const (
	IncidentEvtReviewPass = "review_pass"
	IncidentEvtReviewFail = "review_fail"
	IncidentEvtRemediate  = "remediate"
	IncidentEvtVerifyPass = "verify_pass"
	IncidentEvtVerifyFail = "verify_fail"
	IncidentEvtClose      = "close"
)

var IncidentSM = NewStateMachine("incident", []Transition[int]{
	{IncidentStatusPendingReview, IncidentStatusReviewPassed, IncidentEvtReviewPass},
	{IncidentStatusPendingReview, IncidentStatusReviewFailed, IncidentEvtReviewFail},

	{IncidentStatusReviewPassed, IncidentStatusRemediating, IncidentEvtRemediate},
	{IncidentStatusRemediation, IncidentStatusRemediating, IncidentEvtRemediate},
	{IncidentStatusRemediating, IncidentStatusRemediating, IncidentEvtRemediate},

	{IncidentStatusRemediating, IncidentStatusVerifying, IncidentEvtVerifyPass},
	{IncidentStatusVerifying, IncidentStatusRemediating, IncidentEvtVerifyFail},

	{IncidentStatusPendingReview, IncidentStatusClosed, IncidentEvtClose},
	{IncidentStatusReviewPassed, IncidentStatusClosed, IncidentEvtClose},
	{IncidentStatusReviewFailed, IncidentStatusClosed, IncidentEvtClose},
	{IncidentStatusRemediation, IncidentStatusClosed, IncidentEvtClose},
	{IncidentStatusRemediating, IncidentStatusClosed, IncidentEvtClose},
	{IncidentStatusVerifying, IncidentStatusClosed, IncidentEvtClose},
})
