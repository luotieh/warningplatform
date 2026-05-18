package model

const (
	CircularEvtSubmit       = "submit"
	CircularEvtVerifyPass   = "verify_pass"
	CircularEvtVerifyReject = "verify_reject"
	CircularEvtDistribute   = "distribute"
	CircularEvtComplete     = "complete"
)

var CircularSM = NewStateMachine("circular", []Transition[CircularStatus]{
	{CircularToBeSubmit, CircularToBeVerified, CircularEvtSubmit},
	{CircularRejected, CircularToBeVerified, CircularEvtSubmit},
	{CircularToBeVerified, CircularToBeDistributed, CircularEvtVerifyPass},
	{CircularToBeVerified, CircularRejected, CircularEvtVerifyReject},
	{CircularToBeDistributed, CircularInProgress, CircularEvtDistribute},
	{CircularInProgress, CircularCompleted, CircularEvtComplete},
})

const (
	CircularOrgEvtDispose      = "dispose"
	CircularOrgEvtTimeout      = "timeout"
	CircularOrgEvtRedistribute = "redistribute"
	CircularOrgEvtReviewReady  = "review_ready"
	CircularOrgEvtApprove      = "approve"
	CircularOrgEvtReject       = "reject"
	CircularOrgEvtReset        = "reset"
)

var CircularOrgSM = NewStateMachine("circular_org", []Transition[CircularStatus]{
	{CircularToBeProcessed, CircularDisposed, CircularOrgEvtDispose},
	{CircularToBeProcessed, CircularTimeOut, CircularOrgEvtTimeout},
	{CircularToBeProcessed, CircularRedistributed, CircularOrgEvtRedistribute},
	{CircularDisposed, CircularToBeReviewed, CircularOrgEvtReviewReady},
	{CircularToBeReviewed, CircularReviewed, CircularOrgEvtApprove},
	{CircularToBeReviewed, CircularRejected, CircularOrgEvtReject},
	{CircularRejected, CircularToBeProcessed, CircularOrgEvtReset},
	{CircularRedistributed, CircularToBeProcessed, CircularOrgEvtReset},
})
