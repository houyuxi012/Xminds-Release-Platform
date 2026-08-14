package release

import "testing"

func TestTransitionAllowedEnforcesExactReleaseStateMachine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		from Status
		to   Status
		want bool
	}{
		{name: "draft submit", from: StatusDraft, to: StatusSubmitted, want: true},
		{name: "submitted approve", from: StatusSubmitted, to: StatusApproved, want: true},
		{name: "submitted reject", from: StatusSubmitted, to: StatusRejected, want: true},
		{name: "approved publish", from: StatusApproved, to: StatusPublishing, want: true},
		{name: "publishing complete", from: StatusPublishing, to: StatusPublished, want: true},
		{name: "publishing fail", from: StatusPublishing, to: StatusFailed, want: true},
		{name: "failed authorized retry", from: StatusFailed, to: StatusPublishing, want: true},
		{name: "published cannot return to draft", from: StatusPublished, to: StatusDraft, want: false},
		{name: "draft cannot skip approval", from: StatusDraft, to: StatusApproved, want: false},
		{name: "rejected is terminal", from: StatusRejected, to: StatusSubmitted, want: false},
		{name: "same state is not a transition", from: StatusSubmitted, to: StatusSubmitted, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := TransitionAllowed(test.from, test.to); got != test.want {
				t.Fatalf("TransitionAllowed(%q, %q) = %t, want %t", test.from, test.to, got, test.want)
			}
		})
	}
}
