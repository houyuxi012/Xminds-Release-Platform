package release

func TransitionAllowed(from, to Status) bool {
	switch from {
	case StatusDraft:
		return to == StatusSubmitted
	case StatusSubmitted:
		return to == StatusApproved || to == StatusRejected
	case StatusApproved:
		return to == StatusPublishing
	case StatusPublishing:
		return to == StatusPublished || to == StatusFailed
	case StatusFailed:
		return to == StatusPublishing
	default:
		return false
	}
}
