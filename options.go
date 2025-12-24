package pbnebula

type Options struct {
	// Optional: Override collection names
	AuthorityCollection string
	NodeCollection      string
	GroupCollection     string
	RuleCollection      string
}

func DefaultOptions() Options {
	return Options{
		AuthorityCollection: "nebula_authorities",
		NodeCollection:      "nebula_nodes",
		GroupCollection:     "nebula_groups",
		RuleCollection:      "nebula_rules",
	}
}
