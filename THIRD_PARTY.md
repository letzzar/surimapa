# Third-party components · Componentes de terceros

Surimapa is licensed under GPL-3.0. The following bundled components keep their own licenses.
Surimapa se distribuye bajo GPL-3.0. Los siguientes componentes incluidos mantienen sus propias licencias.

| Component · Componente | Path · Ruta | License · Licencia |
|---|---|---|
| [Leaflet](https://leafletjs.com) 1.9.4 | `deploy/portal/static/vendor/leaflet/` | BSD-2-Clause |
| [Chart.js](https://www.chartjs.org) 4.5.0 | `deploy/portal/static/vendor/chart.umd.min.js` | MIT |
| World map · Mapa mundial ([Natural Earth](https://www.naturalearthdata.com) 1:110m, reduced · reducido) | `deploy/portal/static/vendor/world-110m.geojson` | Public domain · Dominio público |
| MaxMind test databases · Bases de prueba de MaxMind ([MaxMind-DB](https://github.com/maxmind/MaxMind-DB)) | `tests/fixtures/geoip/` | Apache-2.0 / MIT |

Not included · No incluido: **GeoLite2** databases. Each installation downloads them with its own free MaxMind account (GeoLite2 End User License Agreement).
Cada instalación descarga las bases **GeoLite2** con su propia cuenta gratuita de MaxMind (licencia GeoLite2 EULA).
