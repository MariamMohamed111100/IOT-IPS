.PHONY: demo-up demo-scan demo-brute demo-rogue demo-attack demo-block demo-unblock demo-incident setup up down logs ps smoke test lint clean sim-list sim watch ws

setup:        ## Generate .env secrets, TLS certs, MQTT users (safe to re-run)
	./scripts/setup.sh

up:           ## Build and start everything
	@test -f .env || ./scripts/setup.sh
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=50

ps:
	docker compose ps

smoke:        ## Verify every service is alive over MQTT/TLS
	./scripts/smoke-test.sh

test:         ## Unit tests (no Docker needed)
	pip install -q -e libs/common pytest jsonschema pyyaml gpiozero httpx \
	  -r services/api/requirements.txt -r services/vision/requirements.txt \
	  -r services/cyber/requirements.txt
	pytest libs/common/tests services/simulators/tests -q
	pytest services/api/tests -q
	pytest services/vision/tests -q
	pytest services/engine/tests -q
	pytest services/cyber/tests -q

lint:
	ruff check .

sim-list:     ## List simulator scenarios
	docker compose exec simulators python scenario_runner.py --list

sim:          ## Run a scenario:  make sim S=night_intruder
	@test -n "$(S)" || { echo "usage: make sim S=<scenario>  (see: make sim-list)"; exit 1; }
	docker compose exec simulators python scenario_runner.py $(S)

watch:        ## Live-print events:  make watch  (or T='home/#' for everything)
	./scripts/watch.sh $(T)

ws:           ## Live dashboard feed in the terminal (logs in with .env credentials)
	python scripts/ws_listen.py

vision-models: ## Download the free vision models (YOLOv8n, face detector/recognizer) once
	python3 scripts/fetch_vision_models.py

demo-incident: ## Play the proposal's garage-intruder incident end to end (checks the API afterwards)
	python scripts/demo_incident.py

demo-up:      ## Start everything plus the demo rig (attacker, smartlock victim, Suricata, ntfy)
	@test -f .env || ./scripts/setup.sh
	docker compose --profile demo up --build -d

demo-scan:    ## Cyber demo: nmap port scan from the attacker container (cyber.port_scan + block)
	docker compose --profile demo exec attacker attack scan

demo-brute:   ## Cyber demo: hydra brute force against the smart lock (cyber.brute_force + block)
	docker compose --profile demo exec attacker attack brute

demo-rogue:   ## Cyber demo: DHCP request from an unknown MAC (cyber.rogue_device)
	docker compose --profile demo exec attacker attack rogue

demo-attack:  ## Cyber demo: rogue device, then brute force, then scan (the scan gets it blocked)
	docker compose --profile demo exec attacker attack all

demo-block:   ## Ask cyber to block an IP like the engine does:  make demo-block IP=203.0.113.9
	@test -n "$(IP)" || { echo "usage: make demo-block IP=<address>"; exit 1; }
	./scripts/block-admin.sh block $(IP)

demo-unblock: ## Lift a block so the demo can be re-run:  make demo-unblock IP=<attacker ip>
	@test -n "$(IP)" || { echo "usage: make demo-unblock IP=<address>"; exit 1; }
	./scripts/block-admin.sh unblock $(IP)

clean:        ## Stop and delete volumes (DB data is lost)
	docker compose down -v
