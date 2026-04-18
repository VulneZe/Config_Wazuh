# Wazuh Deployer

Assistant interactif complet pour la configuration et le déploiement automatisé de Wazuh, conçu spécifiquement pour l'environnement Obeo selon le guide de déploiement et d'exploitation Wazuh.

## 📋 Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Configuration](#configuration)
- [Déploiement complet](#déploiement-complet)
- [Tests et validation](#tests-et-validation)
- [Mise en production](#mise-en-production)
- [Maintenance](#maintenance)
- [Dépannage](#dépannage)

## 🎯 Vue d'ensemble

Wazuh Deployer est un outil professionnel en Python et Bash qui permet de:

- **Installer** les composants Wazuh (manager, indexer, dashboard)
- **Configurer** l'ensemble de la plateforme selon les meilleures pratiques
- **Analyser** l'environnement et valider les prérequis
- **Vérifier** la cohérence de la configuration
- **Tester** le bon fonctionnement des composants
- **Corriger** automatiquement les erreurs courantes
- **Préparer** la mise en production avec des checklists
- **Générer** des rapports détaillés

L'outil est basé sur le guide de déploiement Wazuh pour Obeo, couvrant les phases 0 à 5 du déploiement.

## ✨ Fonctionnalités

### Assistant Interactif
- Menu principal avec choix numérotés
- Confirmation avant chaque action critique
- Mode dry-run pour simulation
- Mode déploiement complet ou partiel
- Navigation claire entre les étapes

### Détection d'Environnement
- Détection automatique du système d'exploitation
- Analyse des ressources (CPU, RAM, disque)
- Vérification de la connectivité réseau
- Détection des ports disponibles
- Validation des dépendances

### Installation des Composants
- Installation automatique du dépôt Wazuh
- Support Debian/Ubuntu et RHEL/CentOS
- Configuration TLS avec certificats
- Configuration de la heap JVM pour l'indexer
- Démarrage automatique des services

### Configuration Centralisée
- Création automatique des groupes d'agents
- Génération des fichiers agent.conf par groupe
- Validation de la syntaxe avec verify-agent-conf
- Support des labels (site, env, owner, criticality)
- Configuration des modules par groupe

### Socle Technique
- **Syscollector**: Inventaire système complet
- **Vulnerability Detection**: Détection des CVE
- **SCA**: Security Configuration Assessment
- **FIM/Syscheck**: Surveillance d'intégrité de fichiers
- **Collecte de logs**: Journaux d'authentification, système, applications
- **Active Response**: Réponses automatiques contrôlées

### Dashboard
- Création des data views (index patterns)
- Import des dashboards prédéfinis
- Configuration de l'alerting
- Configuration des notifications (email, Slack)
- Configuration du reporting

### Intégrations Cloud/SaaS
- **Docker**: Docker listener et logs
- **AWS**: CloudTrail via S3
- **GCP**: Audit logs via Pub/Sub
- **GitHub**: Audit log d'organisation
- **Office 365**: Audit logs Microsoft 365
- **Microsoft Graph**: Security, incidents, sign-ins

### Vérification et Audit
- Vérification de l'état des services
- Validation des fichiers de configuration
- Vérification de la configuration TLS
- Test de connectivité API
- Vérification de la santé de l'indexer
- Validation de l'accès au dashboard

### Tests Automatisés
- Test de logtest
- Test de syscheck
- Test des modules
- Test de analysisd
- Test de connectivité des agents
- Test de connectivité de l'indexer

### Corrections Automatiques
- Redémarrage des services défaillants
- Correction des permissions
- Ajout de configurations manquantes
- Nettoyage de l'espace disque
- Configuration de la heap JVM

### Mise en Production
- Checklist de pré-production
- Validation des changements de mots de passe par défaut
- Vérification de la configuration RBAC
- Sauvegarde automatique de la configuration
- Génération de rapport de production

## 🏗️ Architecture

```
wazuh-deployer/
├── wazuh_deployer.py              # Point d'entrée principal
├── requirements.txt               # Dépendances Python
├── README.md                      # Documentation
├── .env.example                   # Exemple de configuration
├── config/
│   ├── config.yaml                # Configuration centralisée
│   └── agent_groups.yaml          # Configuration des groupes
├── modules/
│   ├── __init__.py
│   ├── environment_detector.py   # Détection environnement
│   ├── installer.py              # Installation composants
│   ├── config_manager.py          # Gestion configuration
│   ├── technical_base.py          # Socle technique
│   ├── dashboard_config.py        # Configuration dashboard
│   ├── integrations.py            # Intégrations cloud/SaaS
│   ├── verifier.py                # Vérification et audit
│   ├── tester.py                  # Tests et validation
│   ├── auto_corrector.py          # Corrections automatiques
│   └── production.py              # Mise en production
├── scripts/
│   ├── install_wazuh.sh           # Script d'installation
│   ├── configure_tls.sh           # Configuration TLS
│   ├── verify_services.sh         # Vérification services
│   ├── backup_config.sh           # Sauvegarde configuration
│   └── setup_dashboard.sh         # Configuration dashboard
├── templates/
│   ├── agent_default.conf         # Template default
│   ├── agent_linux_servers.conf   # Template linux-servers
│   ├── agent_docker_hosts.conf    # Template docker-hosts
│   ├── local_rules.xml            # Règles locales
│   └── local_decoder.xml          # Décodeurs locaux
├── logs/                          # Logs d'exécution
├── reports/                       # Rapports générés
└── tests/
    └── test_suite.py              # Suite de tests
```

## 📦 Prérequis

### Système
- **OS**: Linux (Debian/Ubuntu 10+, RHEL/CentOS 7+)
- **RAM**: Minimum 4 GB (recommandé 8 GB+ pour production)
- **Disque**: Minimum 20 GB libres
- **CPU**: Minimum 2 cœurs

### Logiciels
- Python 3.7+
- pip3
- curl
- openssl
- systemctl (systemd)
- Accès root ou sudo

### Réseau
- Accès Internet (pour télécharger les paquets Wazuh)
- Ports disponibles: 1514, 15150, 9200, 443

## 🚀 Installation

### 1. Cloner ou télécharger le projet

```bash
cd /opt
git clone <repository-url> wazuh-deployer
cd wazuh-deployer
```

### 2. Installer les dépendances Python

```bash
pip3 install -r requirements.txt
```

### 3. Configurer l'environnement

```bash
# Copier le fichier d'exemple
cp .env.example .env

# Éditer .env avec vos paramètres
nano .env
```

Paramètres importants à modifier:
- `WAZUH_API_PASSWORD`: Mot de passe admin Wazuh
- `INDEXER_PASSWORD`: Mot de passe indexer
- `ENABLE_TLS`: true/false
- `ARCHITECTURE`: all-in-one ou distributed
- Intégrations cloud (si nécessaires)

### 4. Rendre les scripts Bash exécutables

```bash
chmod +x scripts/*.sh
```

## 🎮 Utilisation

### Lancer l'assistant principal

```bash
python3 wazuh_deployer.py
```

### Menu principal

```
==============================================================================
                    WAZUH DEPLOYER v1.0
            Configuration & Deployment Assistant
==============================================================================

Main Menu - Select an option:

  1. Full Deployment (Complete installation and configuration)
  2. Partial Configuration (Configure specific components)
  3. Environment Detection Only
  4. Verification & Audit
  5. Run Tests
  6. Production Checklist
  7. View Current Status
  8. Auto-Correction
  9. Generate Report
  0. Exit
```

### Options détaillées

#### 1. Full Deployment
Déploiement complet en 6 phases:
- Phase 0: Détection environnement
- Phase 1: Installation plateforme
- Phase 2: Configuration agents
- Phase 3: Socle technique
- Phase 4: Dashboard
- Phase 5: Intégrations

#### 2. Partial Configuration
Configuration sélective:
- Agent Groups & Configuration
- Technical Base (SCA, FIM, Logs)
- Dashboard (Data Views, Dashboards)
- Cloud/SaaS Integrations
- Custom Rules & Decoders

#### 3. Environment Detection
Détection et validation de l'environnement uniquement.

#### 4. Verification & Audit
Vérification complète de l'installation.

#### 5. Run Tests
Exécution de la suite de tests.

#### 6. Production Checklist
Validation de la préparation à la production.

#### 7. View Current Status
Affichage de l'état actuel du déploiement.

#### 8. Auto-Correction
Correction automatique des erreurs détectées.

#### 9. Generate Report
Génération d'un rapport détaillé.

## ⚙️ Configuration

### Fichiers de configuration

#### config/config.yaml
Configuration principale du projet:
- Phases de déploiement
- Composants Wazuh
- Groupes d'agents
- Modules techniques
- Configuration dashboard
- Politiques de rétention

#### config/agent_groups.yaml
Configuration détaillée des groupes d'agents:
- Labels par groupe
- Modules activés
- Configuration spécifique
- FIM ciblé
- Logs à collecter

#### .env
Variables d'environnement:
- Credentials API
- Ports et hôtes
- Intégrations cloud
- Configuration TLS
- Notifications

### Groupes d'agents prédéfinis

| Groupe | Description | Usage |
|--------|-------------|-------|
| default | Socle minimal pour tous | Tous les agents |
| linux-servers-prod | Serveurs de production | Services applicatifs |
| linux-servers-infra | Infrastructure | DNS, bastions, VPN |
| linux-dev-workstations | Postes développeurs | Ingénierie |
| rh-office | Postes RH | Données sensibles |
| hypervisors-xen | Hyperviseurs XEN | Virtualisation |
| docker-hosts | Hôtes Docker | Conteneurs |
| exposed-services | Services exposés | Reverse proxies |
| cloud-collectors | Intégrations cloud | AWS, GCP, GitHub, O365 |

## 📋 Déploiement complet

### Phase 0: Cadrage
1. Détection de l'environnement
2. Validation des prérequis
3. Choix de l'architecture (all-in-one vs distributed)
4. Planification de la capacité

### Phase 1: Socle plateforme
1. Installation des composants Wazuh
2. Configuration TLS
3. Configuration RBAC
4. Sauvegardes initiales
5. Monitoring de base

### Phase 2: Agents et groupes
1. Création des groupes d'agents
2. Configuration centralisée (agent.conf)
3. Enrôlement des agents
4. Validation de la configuration

### Phase 3: Socle technique
1. Configuration Syscollector
2. Configuration Vulnerability Detection
3. Configuration SCA
4. Configuration FIM
5. Configuration collecte de logs
6. Configuration Active Response

### Phase 4: Dashboard
1. Création des data views
2. Import des dashboards
3. Configuration de l'alerting
4. Configuration des notifications
5. Configuration du reporting

### Phase 5: Intégrations
1. Configuration Docker (si applicable)
2. Configuration AWS (si applicable)
3. Configuration GCP (si applicable)
4. Configuration GitHub (si applicable)
5. Configuration Office 365 (si applicable)
6. Configuration Microsoft Graph (si applicable)

## 🧪 Tests et validation

### Suite de tests automatisés

```bash
python3 wazuh_deployer.py
# Sélectionner option 5: Run Tests
```

### Tests manuels

#### Test de logtest
```bash
/var/ossec/bin/wazuh-logtest
```

#### Test de syscheck
```bash
/var/ossec/bin/wazuh-syscheckd -t
```

#### Test des modules
```bash
/var/ossec/bin/wazuh-modulesd -t
```

#### Vérification de la configuration
```bash
/var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/default/agent.conf
```

### Vérification des services
```bash
./scripts/verify_services.sh
```

## 🚀 Mise en production

### Checklist de pré-production

1. **Sécurité**
   - [ ] Certificats TLS configurés
   - [ ] Mots de passe par défaut changés
   - [ ] Firewall configuré
   - [ ] RBAC activé

2. **Configuration**
   - [ ] Groupes d'agents créés
   - [ ] Configuration centralisée validée
   - [ ] Socle technique activé
   - [ ] Dashboard configuré

3. **Agents**
   - [ ] Agents critiques enrôlés
   - [ ] Inventaire visible
   - [ ] Vulnérabilités détectées
   - [ ] Logs collectés

4. **Monitoring**
   - [ ] Monitors configurés
   - [ ] Notifications activées
   - [ ] Sauvegardes planifiées
   - [ ] Alertes testées

5. **Documentation**
   - [ ] Runbooks documentés
   - [ ] Architecture documentée
   - [ ] Procédures d'escalade
   - [ ] Points de contact

### Sauvegarde avant production

```bash
./scripts/backup_config.sh
```

### Validation finale

```bash
python3 wazuh_deployer.py
# Sélectionner option 6: Production Checklist
```

## 🔧 Maintenance

### Opérations quotidiennes

1. Vérifier les monitors rouges
2. Vérifier les agents déconnectés
3. Vérifier les erreurs d'ingestion
4. Surveiller l'espace disque

### Opérations hebdomadaires

1. Revoir les règles bruyantes
2. Traiter les faux positifs
3. Vérifier les vulnérabilités critiques
4. Revoir les écarts SCA

### Opérations mensuelles

1. Revoir les rôles et accès
2. Vérifier la capacité stockage
3. Nettoyer les exceptions historiques
4. Tester la restauration

### Mise à jour

```bash
# Sauvegarder avant mise à jour
./scripts/backup_config.sh

# Mettre à jour les paquets
apt-get update && apt-get upgrade wazuh-*  # Debian/Ubuntu
yum update wazuh-*  # RHEL/CentOS

# Redémarrer les services
systemctl restart wazuh-manager
systemctl restart wazuh-indexer
systemctl restart wazuh-dashboard

# Vérifier
./scripts/verify_services.sh
```

## 🐛 Dépannage

### Services ne démarrent pas

```bash
# Vérifier les logs
journalctl -u wazuh-manager -n 50
journalctl -u wazuh-indexer -n 50
journalctl -u wazuh-dashboard -n 50

# Vérifier la configuration
/var/ossec/bin/wazuh-control status
```

### Agents ne se connectent pas

```bash
# Vérifier la connectivité
telnet <manager-ip> 1514

# Vérifier les logs agent
tail -f /var/ossec/logs/ossec.log

# Vérifier la configuration
/var/ossec/bin/agent_control -l
```

### Erreur de mémoire Indexer

```bash
# Ajuster la heap JVM
# Éditer /etc/wazuh-indexer/jvm.options
# Ajouter: -Xms4g -Xmx4g (adapter selon RAM)

systemctl restart wazuh-indexer
```

### Espace disque insuffisant

```bash
# Nettoyer les anciens logs
find /var/ossec/logs -name "*.log*" -mtime +30 -delete

# Ajuster la rétention
# Modifier config/config.yaml -> retention
```

## 📚 Ressources

- [Documentation officielle Wazuh](https://documentation.wazuh.com/)
- [Guide de déploiement Obeo](Guide_Wazuh_Entreprise_Obeo_Baptiste_Rouault.docx)
- [Wazuh GitHub](https://github.com/wazuh/wazuh)

## 📝 Support

Pour les problèmes ou questions:
1. Consulter les logs dans le répertoire `logs/`
2. Générer un rapport avec l'option 9
3. Consulter la documentation officielle Wazuh

## 📄 Licence

Ce projet est développé pour Obeo selon les exigences du guide de déploiement Wazuh.

---

**Version**: 1.0.0  
**Date**: 2026-04-18  
**Auteur**: Obeo Security Team
