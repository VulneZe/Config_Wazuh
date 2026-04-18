# Guide de Test et Validation - Wazuh Deployer

Ce guide décrit les procédures de test et validation pour le projet Wazuh Deployer.

## 📋 Table des matières

- [Tests unitaires](#tests-unitaires)
- [Tests d'intégration](#tests-dintégration)
- [Tests de validation](#tests-de-validation)
- [Tests en production](#tests-en-production)
- [Procédure de validation finale](#procédure-de-validation-finale)

## 🧪 Tests unitaires

### Exécuter la suite de tests unitaires

```bash
cd /opt/wazuh-deployer
python3 tests/test_suite.py
```

### Tests inclus

1. **TestConfigurationFiles**
   - Vérifie l'existence des fichiers de configuration
   - Valide la syntaxe YAML

2. **TestModules**
   - Vérifie l'importabilité de tous les modules Python
   - Valide la structure des modules

3. **TestTemplates**
   - Vérifie l'existence des fichiers templates
   - Valide la syntaxe XML des templates

4. **TestScripts**
   - Vérifie l'existence des scripts Bash
   - Valide les permissions d'exécution

5. **TestMainScript**
   - Vérifie l'existence du script principal

### Résultats attendus

Tous les tests doivent passer (OK). En cas d'échec, vérifier:
- Les fichiers manquants
- Les permissions
- Les dépendances Python

## 🔗 Tests d'intégration

### Test 1: Détection d'environnement

```bash
python3 wazuh_deployer.py
# Sélectionner option 3: Environment Detection Only
```

**Validation attendue:**
- OS détecté correctement
- Ressources (RAM, CPU, disque) affichées
- Réseau fonctionnel
- Ports disponibles
- Dépendances installées

### Test 2: Installation des composants

```bash
# En mode test/sandbox
./scripts/install_wazuh.sh
```

**Validation attendue:**
- Dépôt Wazuh installé
- Paquets installés sans erreur
- Services démarrés
- Ports à l'écoute

### Test 3: Configuration TLS

```bash
./scripts/configure_tls.sh
```

**Validation attendue:**
- Certificats générés
- Permissions correctes
- Services redémarrés
- Communication HTTPS fonctionnelle

### Test 4: Configuration centralisée

```bash
python3 wazuh_deployer.py
# Sélectionner option 2: Partial Configuration
# Sélectionner option 1: Agent Groups & Configuration
```

**Validation attendue:**
- Groupes d'agents créés
- Fichiers agent.conf générés
- Configuration validée (verify-agent-conf)
- Permissions correctes

## ✅ Tests de validation

### Validation 1: Services

```bash
./scripts/verify_services.sh
```

**Critères de succès:**
- wazuh-manager: active
- wazuh-indexer: active
- wazuh-dashboard: active
- Ports 1514, 15150, 9200, 443: à l'écoute

### Validation 2: API Wazuh Manager

```bash
curl -k -u admin:admin https://localhost:15150/
```

**Critère de succès:**
- Réponse HTTP 200
- JSON valide retourné

### Validation 3: API Indexer

```bash
curl -k -u admin:admin https://localhost:9200/_cluster/health
```

**Critères de succès:**
- Réponse HTTP 200
- Status: green ou yellow
- Nombre de nœuds > 0

### Validation 4: Dashboard

```bash
curl -k https://localhost:443/
```

**Critère de succès:**
- Réponse HTTP 200
- Page dashboard chargée

### Validation 5: Configuration Wazuh

```bash
/var/ossec/bin/wazuh-logtest
# Entrer un log de test
```

**Critères de succès:**
- Logtest démarre sans erreur
- Logs parsés correctement

### Validation 6: Configuration agents

```bash
/var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/default/agent.conf
```

**Critère de succès:**
- Pas d'erreur de syntaxe
- Configuration valide

## 🚀 Tests en production

### Test 1: Enrôlement d'un agent

```bash
# Sur l'agent
wget https://<manager-ip>/wazuh-agent.deb
dpkg -i wazuh-agent.deb

# Configurer l'agent
/var/ossec/bin/agent-auth -m <manager-ip> -n <agent-name>

# Démarrer l'agent
systemctl start wazuh-agent
```

**Validation attendue:**
- Agent connecté au manager
- Statut "active" dans le dashboard
- Inventaire remonté

### Test 2: Génération d'alertes

```bash
# Sur l'agent, générer des événements
# Essai de connexion SSH échoué
ssh invalid-user@localhost

# Modification de fichier sensible
echo "test" >> /etc/test
```

**Validation attendue:**
- Alertes visibles dans le dashboard
- Règles déclenchées correctement
- Logs indexés

### Test 3: Intégration cloud (si configurée)

```bash
# Vérifier les logs des intégrations
tail -f /var/ossec/logs/ossec.log | grep -i aws
tail -f /var/ossec/logs/ossec.log | grep -i github
```

**Validation attendue:**
- Événements cloud ingérés
- Pas d'erreur d'authentification
- Logs visibles dans le dashboard

### Test 4: Sauvegarde et restauration

```bash
# Sauvegarde
./scripts/backup_config.sh

# Simuler une restauration (test uniquement)
# Ne pas restaurer sur un système en production
tar -xzf /var/backups/wazuh/backup_*.tar.gz -C /tmp/test_restore
```

**Validation attendue:**
- Sauvegarde créée avec succès
- Archive complète
- Taille raisonnable

## 📝 Procédure de validation finale

### Étape 1: Exécution de la checklist production

```bash
python3 wazuh_deployer.py
# Sélectionner option 6: Production Checklist
```

### Étape 2: Vérification manuelle

#### Sécurité
- [ ] Certificats TLS configurés et valides
- [ ] Mots de passe par défaut changés
- [ ] Firewall actif et configuré
- [ ] Ports non nécessaires fermés
- [ ] RBAC configuré avec rôles appropriés

#### Configuration
- [ ] Tous les groupes d'agents créés
- [ ] Configuration centralisée validée
- [ ] Socle technique activé (Syscollector, Vuln, SCA, FIM)
- [ ] Logs configurés
- [ ] Active Response configuré (si nécessaire)

#### Dashboard
- [ ] Data views créées
- [ ] Dashboards importés
- [ ] Monitors configurés
- [ ] Notifications configurées
- [ ] Reporting configuré

#### Agents
- [ ] Agents critiques enrôlés
- [ ] Inventaire visible et complet
- [ ] Vulnérabilités détectées
- [ ] Logs remontés
- [ ] Pas d'agents déconnectés

#### Intégrations
- [ ] Intégrations cloud testées
- [ ] Secrets stockés sécurisément
- [ ] Fraîcheur des flux vérifiée
- [ ] Pas d'erreur d'authentification

#### Documentation
- [ ] Runbooks documentés
- [ ] Architecture documentée
- [ ] Procédures d'escalade définies
- [ ] Points de contact identifiés

### Étape 3: Tests de charge (optionnel)

```bash
# Simuler une charge d'alertes
# Utiliser un outil de génération de logs
# Surveiller les performances
```

### Étape 4: Validation finale

```bash
python3 wazuh_deployer.py
# Sélectionner option 4: Verification & Audit
# Sélectionner option 5: Run Tests
# Sélectionner option 9: Generate Report
```

### Étape 5: Signature pour production

- [ ] Responsable sécurité valide
- [ ] Responsable infrastructure valide
- [ ] Sponsor métier valide
- [ ] Date de bascule planifiée
- [ ] Procédure de rollback documentée

## 📊 Critères d'acceptation

Le déploiement est considéré comme prêt pour la production lorsque:

1. **Tous les tests unitaires passent** ✓
2. **Tous les services sont actifs** ✓
3. **La configuration est validée** ✓
4. **Les agents critiques sont connectés** ✓
5. **Le dashboard est fonctionnel** ✓
6. **Les sauvegardes sont configurées** ✓
7. **La documentation est complète** ✓
8. **La checklist production est validée** ✓

## 🐛 Gestion des échecs

### Si un test échoue

1. **Identifier la cause**
   - Consulter les logs dans `logs/`
   - Vérifier les messages d'erreur
   - Isoler le composant défaillant

2. **Corriger**
   - Utiliser l'option 8: Auto-Correction
   - Appliquer les corrections manuelles
   - Reconfigurer si nécessaire

3. **Re-tester**
   - Relancer le test échoué
   - Vérifier la correction
   - Valider les composants liés

4. **Documenter**
   - Noter le problème
   - Documenter la solution
   - Mettre à jour les runbooks

### Procédure d'escalade

1. Niveau 1: Opérateur
   - Tests basiques
   - Redémarrage services
   - Vérification logs

2. Niveau 2: Administrateur
   - Configuration avancée
   - Debugging approfondi
   - Contact support Wazuh

3. Niveau 3: Expert
   - Problèmes complexes
   - Architecture
   - Décisions de rollback

## 📈 Rapport de test

Après validation, générer un rapport:

```bash
python3 wazuh_deployer.py
# Sélectionner option 9: Generate Report
```

Le rapport inclura:
- Résumé de l'exécution
- Résultats des tests
- État de la configuration
- Recommandations
- Statut de préparation production

---

**Version**: 1.0.0  
**Date**: 2026-04-18  
**Auteur**: Obeo Security Team
