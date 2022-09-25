package heuristics

import "microscope/formats"

func InsertAnomaly(anomaly string, point int) {

	anomalyToAdd := formats.Anomaly{
		Reason: anomaly,
		Points: point,
	}
	FileAnalyzed.Anomalies = append(FileAnalyzed.Anomalies, anomalyToAdd)
	FileAnalyzed.Score += point
}
