# Geo

Geospatial: geohash, polylines, simplification, geofencing, map matching, tracking.

| Crate | Description |
| --- | --- |
| [`rune-bbox`](rune-bbox) | Bounding-box math: union, intersection, containment, clustering/merge of overlapping boxes |
| [`rune-dwell`](rune-dwell) | Stop/dwell-time detection from a position stream |
| [`rune-eta`](rune-eta) | Distance- and speed-profile-based arrival time estimator |
| [`rune-geo-cluster`](rune-geo-cluster) | Spatial clustering of point sets (thin geo-domain wrapper over the existing ml clustering crates) |
| [`rune-geofence`](rune-geofence) | Point-in-polygon / point-in-circle containment, plus enter/exit event detection over a position stream |
| [`rune-geohash`](rune-geohash) | Geohash encode/decode |
| [`rune-haversine`](rune-haversine) | Great-circle distance and bearing between coordinates |
| [`rune-kalman-track`](rune-kalman-track) | Kalman filter for smoothing noisy position/velocity readings |
| [`rune-map-match`](rune-map-match) | Snap a noisy position stream onto the nearest edges of a supplied road/path graph |
| [`rune-mvt`](rune-mvt) | Encode and decode Mapbox Vector Tile protobuf |
| [`rune-polyline`](rune-polyline) | Google polyline algorithm encode/decode |
| [`rune-rtree`](rune-rtree) | R-tree spatial index for fast nearest-neighbor and range queries over points |
| [`rune-simplify`](rune-simplify) | Douglas-Peucker line simplification for coordinate paths |
| [`rune-static-map`](rune-static-map) | Build static-map image request parameters/URLs from a set of features |
| [`rune-trace-replay`](rune-trace-replay) | Replay a recorded position trace at a configurable speed multiplier through any sink |
| [`rune-tz-lookup`](rune-tz-lookup) | Offline timezone-from-coordinates lookup |

[All groups](../../README.md)
