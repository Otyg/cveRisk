# cveRisk

`TEFCalculator.calculate_tef(cve_id, pressure=None)` tar valfritt ett svar från
FeedSummarys `GET /api/v1/long-term/attack-pressure?profile=...&cve=...`.
`epss` är [FIRST:s ursprungliga 30-dagarssannolikhet](https://www.first.org/epss/faq).
`epss_annual` är en
extrapolering till 365 dagar enligt
`1 - (1 - epss) ** (365 / 30)`; `min`, `mode` och `max` beräknas med
årsvärdet. `annualization_model: constant_30_day_hazard` och
`tef_horizon_days: 365` anger antagandet och horisonten i svaret. Omräkningen
antar konstant risk under året. EPSS uppdateras dagligen och publicerar ingen
kalibrerad årsprognos, så årsvärdet ska tolkas som ett scenario.

Pressure multiplicerar sedan TEF-fälten `min`, `mode` och `max` med den begränsade faktorn
1,0–1,3 och lämnar EPSS/KEV-fälten oförändrade. CVE-ID måste matcha mellan
anropen; `pressure_factor`, `pressure_report_id`, `pressure_components` och
`pressure_weights` returneras för spårbarhet. FeedSummary väger region och
sektor med 0,25 vardera och CVE med 0,50 till den slutliga faktorn.

`python src/cveRisk.py` hämtar nu assessment för varje CVE från
`http://127.0.0.1:5001/api/v1/long-term/attack-pressure` med profilen
`healthcare_europe` och skickar svaret till `calculate_tef`. Om viewern inte
svarar skrivs en varning ut och TEF beräknas utan justering.

```python
pressure = response.json()  # GET från FeedSummarys attack-pressure-endpoint
tef = calculator.calculate_tef("CVE-2026-12345", pressure)
```
