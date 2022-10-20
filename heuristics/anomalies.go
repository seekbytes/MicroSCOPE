package heuristics

import "microscope/formats"

const (
	ANOMALY_FILE_FORMAT = 1
	ANOMALY_IMPORTS     = 2
	ANOMALY_STRINGS     = 3
	ANOMALY_SECTIONS    = 4
	ANOMALY_OTHERS      = 5
)

func InsertAnomaly(anomaly string, point int, category uint) {

	anomalyToAdd := formats.Anomaly{
		Reason: anomaly,
		Points: point,
		Type:   category,
	}
	FileAnalyzed.Anomalies = append(FileAnalyzed.Anomalies, anomalyToAdd)
	FileAnalyzed.Score += point
}

func InsertAnomalyString(anomaly string, point int) {
	InsertAnomaly(anomaly, point, ANOMALY_STRINGS)
}

func InsertAnomalyImports(anomaly string, point int) {
	InsertAnomaly(anomaly, point, ANOMALY_IMPORTS)
}

func InsertAnomalyFileFormat(anomaly string, point int) {
	InsertAnomaly(anomaly, point, ANOMALY_FILE_FORMAT)
}

func InsertAnomalySection(anomaly string, point int) {
	InsertAnomaly(anomaly, point, ANOMALY_SECTIONS)
}

func InsertAnomalyOthers(anomaly string, point int) {
	InsertAnomaly(anomaly, point, ANOMALY_OTHERS)
}
