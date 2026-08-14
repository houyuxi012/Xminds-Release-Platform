package buildinfo

type Info struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

var version = "0.1.0-p0"
var commit = "development"
var buildTime = "unknown"

func Current() Info {
	return Info{
		Product:   "xminds-release-platform",
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
	}
}
