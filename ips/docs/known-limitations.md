# Known limitations

* **Threshold rules.** They cannot see attacks hidden in normal-looking traffic (web attacks) and miss slow attacks under the thresholds. Of the 10 sample attacks, 3 are missed and 2 slow ones are caught only because their port is unexpected for the device. The ML model should cover these.
* **Attack types.** Three of the seven caught sample attacks carry a different type from the dataset label (for example the Mirai flood is reported as DoS).
* **Calibration.** Thresholds and reference scenarios were tuned while looking at the sample events, so results show that the chain works, not how accurate it is.
* **Spoofed trusted source.** Faking an allow-listed or trusted address cannot get it blocked, but it lowers the risk score by up to about 7 points; a borderline Critical event can become High with no automatic block. The incident is still recorded and the administrator notified.
* **Spoofed victim.** An attacker can fake the address of a legitimate outside server that is not on the allow-list to get it temporarily blocked. The active-block cap limits a flood; add the addresses devices depend on to the allow-list.
* **State in memory.** Active blocks are forgotten when the program restarts; the action log keeps the history.
* **Reports** describe every block and isolation as decided in dry-run mode, but the notification still says "Administrator notified" although nothing is sent.
* **False-alarm rate.** The calibration (`docs/calibration-report.md`) uses generated normal traffic anchored on only 4 real benign rows; the spread of Rate is a guess, so the remaining ~1 false DoS alert a day for the camera could be several times higher or zero. Only the camera was baselined; the other five profiles probably also miss DNS and NTP ports.
* **Device profiles.** `THERMO-001`, `PLUG-001` and `IND-001` in `config/devices.json` have guessed ports and protocols.
* **Real blocking** is deliberately not implemented; turning it on needs a reviewed code change.
* **DoS needs many connections.** A flood that arrives as one stream (few counted connections) is missed; sample event EVT-012 is such a case. On live traffic `connection_attempts` must come from the flow engine, and its definition decides how much this rule sees.
* **Direction is trusted.** The unexpected-port rule applies to inbound traffic only, and `direction` comes with the event. Outbound traffic is never judged against the profile, so a compromised device calling a server on an odd port is not flagged. A wrong or forged `direction` in the CSV can hide an unexpected-port event; on live traffic derive it from the device IPs, not from the event.
* **Grouping is per file.** Repeated events are merged when the CSV is processed as a whole. A live service has to update an open incident instead; until then it would create one incident per event.
* **Action result is not hash-protected.** `action_result` is written after the incident was saved, so it is outside the hash chain (like `status`); `actions.jsonl` is the record of what ran.
* **Python.** The pipeline needs Python 3.10+. Only the dataset scripts (`scripts/data`, extra `data`) need 3.11+.
