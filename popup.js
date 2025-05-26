// Enhanced Tab Guard Popup JavaScript with Modern UI
console.log('Tab Guard v3.0 - Modern UI loaded');

class TabGuardUI {
  constructor() {
    this.currentView = 'dashboard';
    this.stats = { threatsBlocked: 0, tabsMonitored: 0, activitiesDetected: 0 };
    this.tabData = {};
    this.threatReports = [];
    this.settings = this.getDefaultSettings();
    this.updateInterval = null;
    
    this.init();
  }

  async init() {
    this.setupEventListeners();
    this.setupNavigation();
    await this.loadInitialData();
    this.startRealTimeUpdates();
    console.log('Tab Guard UI initialized successfully');
  }

  setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-button').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchView(e.target.dataset.view);
      });
    });

    // Dashboard actions
    document.getElementById('refreshDashboard')?.addEventListener('click', () => {
      this.refreshDashboard();
    });

    document.getElementById('masterProtection')?.addEventListener('change', (e) => {
      this.toggleMasterProtection(e.target.checked);
    });

    // Protection view actions
    document.getElementById('quickScanBtn')?.addEventListener('click', () => {
      this.performQuickScan();
    });

    document.getElementById('scanAllBtn')?.addEventListener('click', () => {
      this.scanAllTabs();
    });

    document.getElementById('refreshTabs')?.addEventListener('click', () => {
      this.loadTabsData();
    });

    // Threats view actions
    document.getElementById('threatFilter')?.addEventListener('change', (e) => {
      this.filterThreats(e.target.value);
    });

    document.getElementById('exportThreats')?.addEventListener('click', () => {
      this.exportThreats();
    });

    document.getElementById('clearThreats')?.addEventListener('click', () => {
      this.clearThreats();
    });

    // Settings actions
    document.getElementById('saveSettings')?.addEventListener('click', () => {
      this.saveSettings();
    });

    // Settings toggles
    document.querySelectorAll('#settingsView input[type="checkbox"]').forEach(checkbox => {
      checkbox.addEventListener('change', () => {
        this.updateSettingsPreview();
      });
    });

    document.querySelectorAll('input[name="securityLevel"]').forEach(radio => {
      radio.addEventListener('change', () => {
        this.updateSecurityLevel();
      });
    });

    // Domain management
    document.getElementById('addTrustedDomain')?.addEventListener('click', () => {
      this.addTrustedDomain();
    });

    document.getElementById('addBlockedDomain')?.addEventListener('click', () => {
      this.addBlockedDomain();
    });

    // Action bar
    document.getElementById('emergencyStop')?.addEventListener('click', () => {
      this.emergencyStop();
    });

    document.getElementById('exportData')?.addEventListener('click', () => {
      this.exportAllData();
    });

    document.getElementById('helpSupport')?.addEventListener('click', () => {
      this.showHelp();
    });

    // Enter key handlers for domain inputs
    document.getElementById('trustedDomainInput')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.addTrustedDomain();
    });

    document.getElementById('blockedDomainInput')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.addBlockedDomain();
    });
  }

  setupNavigation() {
    const navButtons = document.querySelectorAll('.nav-button');
    const viewContents = document.querySelectorAll('.view-content');

    navButtons.forEach(button => {
      button.addEventListener('click', () => {
        const targetView = button.dataset.view;
        
        // Update navigation state
        navButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Update view state
        viewContents.forEach(view => view.classList.remove('active'));
        const targetViewElement = document.getElementById(`${targetView}View`);
        if (targetViewElement) {
          targetViewElement.classList.add('active');
          this.currentView = targetView;
          this.loadViewData(targetView);
        }
      });
    });
  }

  async loadInitialData() {
    try {
      await Promise.all([
        this.loadStats(),
        this.loadSettings(),
        this.loadTabsData(),
        this.loadThreatsData()
      ]);
      
      this.updateDashboard();
      this.updateProtectionStatus();
      
    } catch (error) {
      console.error('Error loading initial data:', error);
      this.showError('Failed to load extension data');
    }
  }

  async loadStats() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'GET_MONITORING_DATA' });
      if (response?.success) {
        this.stats = response.realTimeStats || this.stats;
        this.tabData = response.tabData || {};
        this.updateStatsDisplay();
      }
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['tabGuardSettings']);
      this.settings = { ...this.getDefaultSettings(), ...result.tabGuardSettings };
      this.updateSettingsUI();
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  async loadTabsData() {
    if (this.currentView !== 'protection') return;
    
    const container = document.getElementById('tabsContainer');
    if (!container) return;

    container.innerHTML = '<div class="loading-state"><div class="loading-spinner"></div><span>Loading tabs...</span></div>';

    try {
      const [tabs, response] = await Promise.all([
        chrome.tabs.query({}),
        chrome.runtime.sendMessage({ action: 'GET_MONITORING_DATA' })
      ]);

      if (response?.success) {
        this.tabData = response.tabData || {};
        this.renderTabsList(tabs);
      }
    } catch (error) {
      console.error('Error loading tabs:', error);
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">⚠️</div><div class="empty-title">Failed to load tabs</div></div>';
    }
  }

  async loadThreatsData() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'GET_THREAT_REPORTS' });
      if (response?.success) {
        this.threatReports = response.reports || [];
        this.updateThreatsDisplay();
      }
    } catch (error) {
      console.error('Error loading threats:', error);
    }
  }

  loadViewData(viewName) {
    switch (viewName) {
      case 'dashboard':
        this.updateDashboard();
        break;
      case 'protection':
        this.loadTabsData();
        break;
      case 'threats':
        this.updateThreatsDisplay();
        break;
      case 'settings':
        this.updateSettingsUI();
        break;
    }
  }

  updateStatsDisplay() {
    this.animateNumber('threatsBlocked', this.stats.threatsBlocked || 0);
    this.animateNumber('tabsMonitored', this.stats.tabsMonitored || 0);
    this.animateNumber('activitiesDetected', this.stats.activitiesDetected || 0);
    
    // Update security level
    const securityElement = document.getElementById('securityLevel');
    const indicatorElement = document.getElementById('securityIndicator');
    
    if (securityElement && indicatorElement) {
      const level = this.calculateSecurityLevel();
      securityElement.textContent = level.toUpperCase();
      indicatorElement.className = `security-indicator ${level}`;
    }

    // Update protection badge
    this.updateProtectionBadge();
  }

  updateDashboard() {
    this.updateThreatLevelDisplay();
    this.updateRecentActivity();
    this.updateProtectionModules();
  }

  updateThreatLevelDisplay() {
    const threatLevel = this.calculateOverallThreatLevel();
    const threatRing = document.getElementById('threatRing');
    const threatText = document.getElementById('threatLevelText');
    const riskScore = document.getElementById('riskScore');
    const activeThreats = document.getElementById('activeThreats');

    if (threatRing && threatText) {
      const colors = {
        low: '#10b981',
        medium: '#f59e0b', 
        high: '#ef4444',
        critical: '#dc2626'
      };

      const percentage = Math.min((threatLevel.score / 100) * 360, 360);
      threatRing.style.background = `conic-gradient(${colors[threatLevel.level]} 0deg ${percentage}deg, var(--gray-200) ${percentage}deg 360deg)`;
      threatText.textContent = threatLevel.level.toUpperCase();
      threatText.style.color = colors[threatLevel.level];
    }

    if (riskScore) riskScore.textContent = threatLevel.score;
    if (activeThreats) activeThreats.textContent = this.getActiveThreatsCount();
  }

  updateRecentActivity() {
    const container = document.getElementById('recentActivity');
    if (!container) return;

    const recentActivities = this.getRecentActivities(5);
    
    if (recentActivities.length === 0) {
      container.innerHTML = `
        <div class="activity-item safe">
          <div class="activity-icon">✅</div>
          <div class="activity-content">
            <div class="activity-title">All Systems Normal</div>
            <div class="activity-time">No threats detected</div>
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = recentActivities.map(activity => `
      <div class="activity-item ${this.getActivitySeverityClass(activity.severity)}">
        <div class="activity-icon">${this.getActivityIcon(activity.type)}</div>
        <div class="activity-content">
          <div class="activity-title">${this.formatActivityType(activity.type)}</div>
          <div class="activity-time">${this.formatTimeAgo(activity.timestamp)}</div>
        </div>
      </div>
    `).join('');
  }

  updateProtectionModules() {
    const container = document.getElementById('protectionModules');
    if (!container) return;

    const modules = [
      { key: 'cryptoMining', name: 'Crypto Mining Detection', icon: '🔍' },
      { key: 'clipboardProtection', name: 'Clipboard Protection', icon: '📋' },
      { key: 'phishingProtection', name: 'Phishing Shield', icon: '🎣' },
      { key: 'networkMonitoring', name: 'Network Monitor', icon: '🌐' },
      { key: 'formMonitoring', name: 'Form Monitor', icon: '📝' }
    ];

    container.innerHTML = modules.map(module => `
      <div class="module-item ${this.settings[module.key] ? 'active' : ''}">
        <div class="module-icon">${module.icon}</div>
        <div class="module-info">
          <div class="module-name">${module.name}</div>
          <div class="module-status">${this.settings[module.key] ? 'Active' : 'Inactive'}</div>
        </div>
        <div class="module-indicator ${this.settings[module.key] ? 'active' : ''}"></div>
      </div>
    `).join('');
  }

  renderTabsList(tabs) {
    const container = document.getElementById('tabsContainer');
    if (!container) return;

    if (tabs.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">📱</div><div class="empty-title">No tabs to monitor</div></div>';
      return;
    }

    const tabItems = tabs.map(tab => {
      const tabInfo = this.tabData[tab.id] || { riskScore: 0, threatLevel: 'safe', suspiciousActivities: [] };
      const activityCount = tabInfo.suspiciousActivities?.length || 0;
      
      return `
        <div class="tab-item ${tabInfo.threatLevel}" data-tab-id="${tab.id}">
          <div class="tab-title" title="${this.escapeHtml(tab.title || 'Untitled')}">${this.truncateText(tab.title || 'Untitled', 45)}</div>
          <div class="tab-url" title="${this.escapeHtml(tab.url || '')}">${this.truncateText(this.extractDomain(tab.url || ''), 35)}</div>
          <div class="tab-meta">
            <span>Risk: ${tabInfo.riskScore}</span>
            <span>${activityCount} activities</span>
          </div>
        </div>
      `;
    }).join('');

    container.innerHTML = tabItems;

    // Add click handlers for tabs
    container.querySelectorAll('.tab-item').forEach(item => {
      item.addEventListener('click', () => {
        const tabId = parseInt(item.dataset.tabId);
        this.showTabDetails(tabId);
      });
    });
  }

  updateThreatsDisplay() {
    this.updateThreatSummary();
    this.updateThreatsList();
  }

  updateThreatSummary() {
    const summary = this.categorizeThreatsBySeverity();
    
    document.getElementById('criticalThreats').textContent = summary.critical;
    document.getElementById('highThreats').textContent = summary.high;
    document.getElementById('mediumThreats').textContent = summary.medium;
    document.getElementById('lowThreats').textContent = summary.low;
  }

  updateThreatsList() {
    const container = document.getElementById('threatsList');
    const filter = document.getElementById('threatFilter')?.value || 'all';
    
    if (!container) return;

    let filteredThreats = this.threatReports;
    if (filter !== 'all') {
      filteredThreats = this.threatReports.filter(threat => 
        this.getThreatSeverity(threat.data.riskScore) === filter
      );
    }

    if (filteredThreats.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">🛡️</div><div class="empty-title">No threats detected</div><div class="empty-subtitle">Your browsing is secure</div></div>';
      return;
    }

    container.innerHTML = filteredThreats.map(threat => `
      <div class="threat-item ${this.getThreatSeverity(threat.data.riskScore)}">
        <div class="threat-header">
          <div class="threat-type">${this.formatActivityType(threat.type)}</div>
          <div class="threat-time">${this.formatTimeAgo(threat.timestamp)}</div>
        </div>
        <div class="threat-domain">${this.extractDomain(threat.data.url || threat.data.domain || '')}</div>
        <div class="threat-details">${this.formatThreatDetails(threat)}</div>
        <div class="threat-actions">
          <span class="threat-severity ${this.getThreatSeverity(threat.data.riskScore)}">${this.getThreatSeverity(threat.data.riskScore).toUpperCase()}</span>
          <span class="threat-status">${threat.blocked ? '🛡️ Blocked' : '⚠️ Allowed'}</span>
        </div>
      </div>
    `).join('');
  }

  updateSettingsUI() {
    // Update checkboxes
    Object.keys(this.settings).forEach(key => {
      const element = document.getElementById(key);
      if (element && element.type === 'checkbox') {
        element.checked = this.settings[key];
      }
    });

    // Update security level radio
    const securityLevel = this.settings.threatLevel || 'medium';
    const radio = document.querySelector(`input[name="securityLevel"][value="${securityLevel}"]`);
    if (radio) radio.checked = true;

    // Update domain lists
    this.updateDomainLists();
  }

  updateDomainLists() {
    this.renderDomainList('trustedDomainsList', this.settings.whitelistedDomains || [], 'trusted');
    this.renderDomainList('blockedDomainsList', this.settings.blockedDomains || [], 'blocked');
  }

  renderDomainList(containerId, domains, type) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (domains.length === 0) {
      container.innerHTML = `<div class="empty-domain-list">No ${type} domains</div>`;
      return;
    }

    container.innerHTML = domains.map(domain => `
      <div class="domain-tag">
        <span>${this.escapeHtml(domain)}</span>
        <button class="domain-remove" onclick="tabGuardUI.removeDomain('${this.escapeHtml(domain)}', '${type}')">×</button>
      </div>
    `).join('');
  }

  // Action Methods
  async performQuickScan() {
    const btn = document.getElementById('quickScanBtn');
    if (!btn) return;

    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="btn-icon">⏳</span><span>Scanning...</span>';
    btn.disabled = true;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        await chrome.runtime.sendMessage({ action: 'DEEP_SCAN', tabId: tab.id });
        this.showNotification('Quick scan completed', 'success');
        await this.loadTabsData();
      }
    } catch (error) {
      console.error('Quick scan failed:', error);
      this.showNotification('Quick scan failed', 'error');
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }

  async scanAllTabs() {
    const btn = document.getElementById('scanAllBtn');
    if (!btn) return;

    const originalText = btn.innerHTML;
    btn.innerHTML = 'Scanning...';
    btn.disabled = true;

    try {
      const tabs = await chrome.tabs.query({});
      let scannedCount = 0;

      for (const tab of tabs) {
        try {
          await chrome.runtime.sendMessage({ action: 'DEEP_SCAN', tabId: tab.id });
          scannedCount++;
        } catch (error) {
          console.warn(`Failed to scan tab ${tab.id}`);
        }
      }

      this.showNotification(`Scanned ${scannedCount} tabs`, 'success');
      await this.loadTabsData();
    } catch (error) {
      console.error('Scan all failed:', error);
      this.showNotification('Scan failed', 'error');
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }

  async saveSettings() {
    const btn = document.getElementById('saveSettings');
    if (!btn) return;

    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="btn-icon">💾</span><span>Saving...</span>';
    btn.disabled = true;

    try {
      // Collect settings from UI
      const newSettings = {
        ...this.settings,
        cryptoMining: document.getElementById('cryptoMining')?.checked || false,
        clipboardProtection: document.getElementById('clipboardProtection')?.checked || false,
        formMonitoring: document.getElementById('formMonitoring')?.checked || false,
        phishingProtection: document.getElementById('phishingProtection')?.checked || false,
        networkMonitoring: document.getElementById('networkMonitoring')?.checked || false,
        notifications: document.getElementById('notifications')?.checked || false,
        threatLevel: document.querySelector('input[name="securityLevel"]:checked')?.value || 'medium'
      };

      await chrome.storage.local.set({ tabGuardSettings: newSettings });
      this.settings = newSettings;
      
      this.showNotification('Settings saved successfully', 'success');
      this.updateProtectionStatus();
      this.updateDashboard();
    } catch (error) {
      console.error('Save settings failed:', error);
      this.showNotification('Failed to save settings', 'error');
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }

  async addTrustedDomain() {
    const input = document.getElementById('trustedDomainInput');
    if (!input) return;

    const domain = input.value.trim();
    if (!this.isValidDomain(domain)) {
      this.showNotification('Please enter a valid domain', 'error');
      return;
    }

    if (!this.settings.whitelistedDomains) {
      this.settings.whitelistedDomains = [];
    }

    if (this.settings.whitelistedDomains.includes(domain)) {
      this.showNotification('Domain already exists', 'error');
      return;
    }

    this.settings.whitelistedDomains.push(domain);
    await chrome.storage.local.set({ tabGuardSettings: this.settings });
    
    input.value = '';
    this.updateDomainLists();
    this.showNotification('Domain added to trusted list', 'success');
  }

  async addBlockedDomain() {
    const input = document.getElementById('blockedDomainInput');
    if (!input) return;

    const domain = input.value.trim();
    if (!this.isValidDomain(domain)) {
      this.showNotification('Please enter a valid domain', 'error');
      return;
    }

    if (!this.settings.blockedDomains) {
      this.settings.blockedDomains = [];
    }

    if (this.settings.blockedDomains.includes(domain)) {
      this.showNotification('Domain already blocked', 'error');
      return;
    }

    this.settings.blockedDomains.push(domain);
    await chrome.storage.local.set({ tabGuardSettings: this.settings });
    
    input.value = '';
    this.updateDomainLists();
    this.showNotification('Domain added to blocked list', 'success');
  }

  async removeDomain(domain, type) {
    try {
      if (type === 'trusted') {
        this.settings.whitelistedDomains = this.settings.whitelistedDomains.filter(d => d !== domain);
      } else {
        this.settings.blockedDomains = this.settings.blockedDomains.filter(d => d !== domain);
      }

      await chrome.storage.local.set({ tabGuardSettings: this.settings });
      this.updateDomainLists();
      this.showNotification(`Domain removed from ${type} list`, 'success');
    } catch (error) {
      console.error('Remove domain failed:', error);
      this.showNotification('Failed to remove domain', 'error');
    }
  }

  async emergencyStop() {
    if (!confirm('This will disable all protection modules. Are you sure?')) {
      return;
    }

    try {
      const disabledSettings = { ...this.settings };
      Object.keys(disabledSettings).forEach(key => {
        if (typeof disabledSettings[key] === 'boolean') {
          disabledSettings[key] = false;
        }
      });

      await chrome.storage.local.set({ tabGuardSettings: disabledSettings });
      this.settings = disabledSettings;
      
      this.updateSettingsUI();
      this.updateProtectionStatus();
      this.updateDashboard();
      
      this.showNotification('All protection disabled', 'warning');
    } catch (error) {
      console.error('Emergency stop failed:', error);
      this.showNotification('Emergency stop failed', 'error');
    }
  }

  async exportAllData() {
    try {
      const data = {
        settings: this.settings,
        threatReports: this.threatReports,
        stats: this.stats,
        exportDate: new Date().toISOString()
      };

      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const filename = `tab-guard-export-${new Date().toISOString().split('T')[0]}.json`;

      await chrome.downloads.download({ url, filename });
      this.showNotification('Data exported successfully', 'success');
    } catch (error) {
      console.error('Export failed:', error);
      this.showNotification('Export failed', 'error');
    }
  }

  showHelp() {
    const helpContent = `
      Tab Guard v3.0 - Help & Support
      
      🛡️ Protection Modules:
      • Crypto Mining: Detects cryptocurrency mining scripts
      • Clipboard: Monitors unauthorized clipboard access
      • Phishing: Blocks known phishing sites
      • Network: Monitors suspicious requests
      • Forms: Detects automatic form submissions
      
      ⚙️ Security Levels:
      • Basic: Light protection, minimal alerts
      • Standard: Balanced protection
      • Maximum: Highest security, strict monitoring
      
      📊 Dashboard:
      • Real-time threat statistics
      • Current protection status
      • Recent security events
      
      For more help, visit our documentation.
    `;
    
    alert(helpContent);
  }

  // Utility Methods
  switchView(viewName) {
    this.currentView = viewName;
    // View switching is handled by setupNavigation
  }

  startRealTimeUpdates() {
    this.updateInterval = setInterval(() => {
      this.loadStats();
      if (this.currentView === 'protection') {
        this.updateMonitoringMetrics();
      }
    }, 5000);
  }

  updateMonitoringMetrics() {
    // Update network requests count
    const networkElement = document.getElementById('networkRequests');
    if (networkElement) {
      const count = Object.values(this.tabData).reduce((sum, tab) => 
        sum + (tab.networkRequests?.length || 0), 0);
      networkElement.textContent = count;
    }

    // Update CPU usage status
    const cpuElement = document.getElementById('cpuUsage');
    if (cpuElement) {
      const highCpuTabs = Object.values(this.tabData).filter(tab => 
        tab.riskScore > 50);
      cpuElement.textContent = highCpuTabs.length > 0 ? 'High' : 'Normal';
    }

    // Update memory usage (simulated)
    const memoryElement = document.getElementById('memoryUsage');
    if (memoryElement) {
      memoryElement.textContent = 'Normal';
    }
  }

  updateProtectionBadge() {
    const badge = document.getElementById('protectionBadge');
    const protectionCount = Object.values(this.settings).filter(v => v === true).length;
    
    if (badge) {
      if (protectionCount === 0) {
        badge.className = 'protection-badge danger';
        badge.querySelector('.badge-text').textContent = 'Disabled';
      } else if (protectionCount < 3) {
        badge.className = 'protection-badge warning';
        badge.querySelector('.badge-text').textContent = 'Partial';
      } else {
        badge.className = 'protection-badge active';
        badge.querySelector('.badge-text').textContent = 'Protected';
      }
    }
  }

  updateProtectionStatus() {
    this.updateProtectionBadge();
    this.updateProtectionModules();
  }

  animateNumber(elementId, newValue) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const currentValue = parseInt(element.textContent) || 0;
    const difference = newValue - currentValue;
    const steps = 20;
    const stepValue = difference / steps;
    let currentStep = 0;

    const animation = setInterval(() => {
      currentStep++;
      const value = Math.round(currentValue + (stepValue * currentStep));
      element.textContent = value;

      if (currentStep >= steps) {
        element.textContent = newValue;
        clearInterval(animation);
      }
    }, 50);
  }

  calculateSecurityLevel() {
    const activeProtections = Object.values(this.settings).filter(v => v === true).length;
    const totalProtections = 6; // Number of boolean settings
    
    const percentage = (activeProtections / totalProtections) * 100;
    
    if (percentage >= 80) return 'high';
    if (percentage >= 50) return 'medium';
    return 'low';
  }

  calculateOverallThreatLevel() {
    let maxRiskScore = 0;
    let threatCount = 0;

    Object.values(this.tabData).forEach(tab => {
      if (tab.riskScore > maxRiskScore) maxRiskScore = tab.riskScore;
      if (tab.suspiciousActivities?.length > 0) threatCount++;
    });

    let level = 'low';
    if (maxRiskScore >= 80 || threatCount >= 3) level = 'critical';
    else if (maxRiskScore >= 60 || threatCount >= 2) level = 'high';
    else if (maxRiskScore >= 30 || threatCount >= 1) level = 'medium';

    return { level, score: maxRiskScore };
  }

  getActiveThreatsCount() {
    return Object.values(this.tabData).filter(tab => 
      tab.suspiciousActivities?.length > 0).length;
  }

  getRecentActivities(limit = 5) {
    // Simulate recent activities from threat reports
    return this.threatReports
      .slice(-limit)
      .reverse()
      .map(threat => ({
        type: threat.type,
        severity: this.getThreatSeverity(threat.data.riskScore),
        timestamp: threat.timestamp
      }));
  }

  categorizeThreatsBySeverity() {
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    
    this.threatReports.forEach(threat => {
      const severity = this.getThreatSeverity(threat.data.riskScore);
      summary[severity]++;
    });

    return summary;
  }

  getThreatSeverity(riskScore) {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 30) return 'medium';
    return 'low';
  }

  getActivitySeverityClass(severity) {
    const classes = {
      low: 'safe',
      medium: 'warning',
      high: 'warning',
      critical: 'danger'
    };
    return classes[severity] || 'safe';
  }

  getActivityIcon(type) {
    const icons = {
      'CRYPTO_MINING_DETECTED': '⛏️',
      'CLIPBOARD_ACCESS': '📋',
      'AUTO_FORM_SUBMISSION': '📝',
      'PHISHING_ATTEMPT': '🎣',
      'SUSPICIOUS_DOWNLOAD': '📥',
      'MALICIOUS_SCRIPT': '🐛',
      'NETWORK_REQUEST': '🌐'
    };
    return icons[type] || '⚠️';
  }

  formatActivityType(type) {
    const names = {
      'CRYPTO_MINING_DETECTED': 'Crypto Mining Detected',
      'CLIPBOARD_ACCESS': 'Clipboard Access',
      'AUTO_FORM_SUBMISSION': 'Auto Form Submission',
      'PHISHING_ATTEMPT': 'Phishing Attempt',
      'SUSPICIOUS_DOWNLOAD': 'Suspicious Download',
      'MALICIOUS_SCRIPT': 'Malicious Script',
      'NETWORK_REQUEST': 'Network Request'
    };
    return names[type] || type.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
  }

  formatThreatDetails(threat) {
    const details = [];
    if (threat.data.domain) details.push(`Domain: ${threat.data.domain}`);
    if (threat.data.riskScore) details.push(`Risk: ${threat.data.riskScore}`);
    if (threat.data.reason) details.push(`Reason: ${threat.data.reason}`);
    return details.join(' • ') || 'No additional details';
  }

  formatTimeAgo(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'Just now';
  }

  refreshDashboard() {
    const btn = document.getElementById('refreshDashboard');
    if (btn) {
      const originalContent = btn.innerHTML;
      btn.innerHTML = '<span class="btn-icon">⏳</span><span>Refreshing...</span>';
      btn.disabled = true;

      setTimeout(async () => {
        await this.loadInitialData();
        btn.innerHTML = originalContent;
        btn.disabled = false;
        this.showNotification('Dashboard refreshed', 'success');
      }, 1000);
    }
  }

  showTabDetails(tabId) {
    const tabInfo = this.tabData[tabId];
    if (!tabInfo) {
      this.showNotification('No monitoring data available for this tab', 'warning');
      return;
    }

    const activities = tabInfo.suspiciousActivities || [];
    const details = `
      Tab Monitoring Details
      
      Risk Score: ${tabInfo.riskScore}
      Threat Level: ${tabInfo.threatLevel.toUpperCase()}
      Suspicious Activities: ${activities.length}
      
      ${activities.length > 0 ? 'Recent Activities:\n' + activities.slice(-3).map(a => 
        `• ${this.formatActivityType(a.type)} (${this.formatTimeAgo(a.timestamp)})`
      ).join('\n') : 'No suspicious activities detected.'}
    `;

    alert(details);
  }

  filterThreats(filter) {
    this.updateThreatsList();
  }

  async clearThreats() {
    if (!confirm('Are you sure you want to clear all threat reports?')) {
      return;
    }

    try {
      await chrome.storage.local.set({ threatReports: [] });
      this.threatReports = [];
      this.updateThreatsDisplay();
      this.showNotification('Threat reports cleared', 'success');
    } catch (error) {
      console.error('Clear threats failed:', error);
      this.showNotification('Failed to clear threats', 'error');
    }
  }

  async exportThreats() {
    try {
      const data = {
        threats: this.threatReports,
        summary: this.categorizeThreatsBySeverity(),
        exportDate: new Date().toISOString()
      };

      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const filename = `tab-guard-threats-${new Date().toISOString().split('T')[0]}.json`;

      await chrome.downloads.download({ url, filename });
      this.showNotification('Threats exported successfully', 'success');
    } catch (error) {
      console.error('Export threats failed:', error);
      this.showNotification('Export failed', 'error');
    }
  }

  toggleMasterProtection(enabled) {
    // Update all protection settings
    const protectionKeys = ['cryptoMining', 'clipboardProtection', 'formMonitoring', 'phishingProtection', 'networkMonitoring'];
    
    protectionKeys.forEach(key => {
      this.settings[key] = enabled;
      const element = document.getElementById(key);
      if (element) element.checked = enabled;
    });

    this.updateProtectionStatus();
    this.showNotification(`Protection ${enabled ? 'enabled' : 'disabled'}`, enabled ? 'success' : 'warning');
  }

  updateSettingsPreview() {
    // Real-time preview of settings changes
    const activeCount = document.querySelectorAll('#settingsView input[type="checkbox"]:checked').length;
    const securityLevel = document.querySelector('input[name="securityLevel"]:checked')?.value || 'medium';
    
    // Update preview indicators (if any)
    console.log(`Settings preview: ${activeCount} protections active, ${securityLevel} security level`);
  }

  updateSecurityLevel() {
    const level = document.querySelector('input[name="securityLevel"]:checked')?.value;
    if (level) {
      this.settings.threatLevel = level;
      console.log(`Security level changed to: ${level}`);
    }
  }

  showNotification(message, type = 'info') {
    // Create a simple toast notification
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#3b82f6'};
      color: white;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      z-index: 1000;
      animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  showError(message) {
    this.showNotification(message, 'error');
  }

  getDefaultSettings() {
    return {
      cryptoMining: true,
      clipboardProtection: true,
      formMonitoring: true,
      phishingProtection: true,
      networkMonitoring: true,
      notifications: true,
      threatLevel: 'medium',
      whitelistedDomains: [],
      blockedDomains: []
    };
  }

  // Utility helper methods
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  truncateText(text, maxLength) {
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
    return domainRegex.test(domain);
  }
}

// Initialize the modern UI when DOM is loaded
let tabGuardUI;
document.addEventListener('DOMContentLoaded', () => {
  tabGuardUI = new TabGuardUI();
  
  // Add CSS animations
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(100%); opacity: 0; }
    }
  `;
  document.head.appendChild(style);
});

// Cleanup on unload
window.addEventListener('beforeunload', () => {
  if (tabGuardUI?.updateInterval) {
    clearInterval(tabGuardUI.updateInterval);
  }
});