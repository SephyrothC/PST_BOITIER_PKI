# Makefile principal pour PST PKI HSM (Docker)

.PHONY: all build start stop restart logs shell-hsm shell-client test clean help certs

# Configuration
DOCKER_COMPOSE = docker-compose
HSM_CONTAINER = pki-hsm
CLIENT_CONTAINER = pki-client-dev

# Couleurs pour l'affichage
BLUE = \033[0;34m
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

all: help

## Build: Construit toutes les images Docker
build:
	@echo "$(BLUE)Building Docker images...$(NC)"
	@./scripts/build-all.sh

## Start: Démarre l'environnement complet
start:
	@echo "$(BLUE)Starting development environment...$(NC)"
	@./scripts/start-dev.sh

## Stop: Arrête l'environnement
stop:
	@echo "$(BLUE)Stopping environment...$(NC)"
	@./scripts/stop-dev.sh

## Restart: Redémarre l'environnement
restart: stop start

## Logs: Affiche les logs des conteneurs
logs:
	@$(DOCKER_COMPOSE) logs -f

logs-hsm:
	@$(DOCKER_COMPOSE) logs -f $(HSM_CONTAINER)

logs-client:
	@$(DOCKER_COMPOSE) logs -f $(CLIENT_CONTAINER)

## Shell: Ouvre un shell dans le conteneur HSM
shell-hsm:
	@$(DOCKER_COMPOSE) exec $(HSM_CONTAINER) /bin/bash

## Shell: Ouvre un shell dans le conteneur client
shell-client:
	@$(DOCKER_COMPOSE) exec $(CLIENT_CONTAINER) /bin/bash

## Test: Lance les tests
test:
	@echo "$(BLUE)Running tests...$(NC)"
	@$(DOCKER_COMPOSE) exec $(HSM_CONTAINER) /opt/pki-hsm/build/test_crypto || true
	@$(DOCKER_COMPOSE) exec $(HSM_CONTAINER) /opt/pki-hsm/build/test_pkcs11 || true

## Status: Affiche le statut des conteneurs
status:
	@$(DOCKER_COMPOSE) ps

## Certs: Génère les certificats TLS
certs:
	@echo "$(BLUE)Generating TLS certificates...$(NC)"
	@./certs/generate-certs.sh

## Clean: Nettoie tout (conteneurs, volumes, images)
clean:
	@echo "$(YELLOW)⚠️  This will remove all containers, volumes, and data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "$(RED)Cleaning...$(NC)"; \
		$(DOCKER_COMPOSE) down -v --rmi all; \
		echo "$(GREEN)✓ Cleaned$(NC)"; \
	else \
		echo "Cancelled."; \
	fi

## Rebuild: Rebuild complet et redémarrage
rebuild:
	@echo "$(BLUE)Rebuilding...$(NC)"
	@$(DOCKER_COMPOSE) down
	@$(DOCKER_COMPOSE) build --no-cache
	@$(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)✓ Rebuilt and restarted$(NC)"

## Backup: Sauvegarde les clés HSM
backup:
	@echo "$(BLUE)Backing up HSM keys...$(NC)"
	@mkdir -p backups
	@docker cp $(HSM_CONTAINER):/var/lib/pki-hsm/keys backups/keys-$(shell date +%Y%m%d-%H%M%S)
	@echo "$(GREEN)✓ Backup created in backups/$(NC)"

## Inspect: Inspecte la configuration
inspect:
	@echo "$(BLUE)=== Docker Compose Configuration ===$(NC)"
	@$(DOCKER_COMPOSE) config
	@echo ""
	@echo "$(BLUE)=== Network Configuration ===$(NC)"
	@docker network inspect pst_boitier_pki_pki-network 2>/dev/null || echo "Network not created yet"

## Health: Vérifie la santé des services
health:
	@echo "$(BLUE)Checking service health...$(NC)"
	@echo ""
	@echo "HSM Server:"
	@docker inspect --format='{{.State.Health.Status}}' $(HSM_CONTAINER) 2>/dev/null || echo "Not running"
	@echo ""
	@echo "Containers:"
	@$(DOCKER_COMPOSE) ps

## Help: Affiche l'aide
help:
	@echo "$(GREEN)╔═══════════════════════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║     PST PKI HSM - Docker Development Commands        ║$(NC)"
	@echo "$(GREEN)╚═══════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(BLUE)Quick Start:$(NC)"
	@echo "  make certs      # Generate TLS certificates"
	@echo "  make build      # Build Docker images"
	@echo "  make start      # Start environment"
	@echo ""
	@echo "$(BLUE)Development:$(NC)"
	@echo "  make logs       # View all logs"
	@echo "  make logs-hsm   # View HSM logs only"
	@echo "  make shell-hsm  # Open shell in HSM container"
	@echo "  make test       # Run tests"
	@echo "  make status     # Show container status"
	@echo ""
	@echo "$(BLUE)Maintenance:$(NC)"
	@echo "  make restart    # Restart environment"
	@echo "  make rebuild    # Full rebuild"
	@echo "  make backup     # Backup HSM keys"
	@echo "  make clean      # Remove everything"
	@echo ""
	@echo "$(BLUE)Inspection:$(NC)"
	@echo "  make health     # Check service health"
	@echo "  make inspect    # Inspect configuration"
	@echo ""
	@echo "For more information, see README.md"
	@echo ""
