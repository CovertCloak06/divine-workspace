/**
 * DVN Code Academy - Progress Tracker
 * Handles user progress persistence, streak tracking, badges, and statistics
 * ref:academy.js, tutorial-engine.js, index.html
 */

class ProgressTracker {
  constructor() {
    this.storageKey = 'dvn_academy_progress'; // localStorage key for saving progress
    this.progress = this.getDefaultProgress(); // Initialize with default structure
    this.loadProgress(); // Load saved progress from localStorage
  }

  /**
   * Get default progress structure
   * Used for new users or reset
   */
  getDefaultProgress() {
    return {
      user: {
        id: this.generateUserId(), // Unique user identifier
        createdAt: new Date().toISOString(), // Account creation date
        lastActive: new Date().toISOString(), // Last activity timestamp
      },
      paths: {
        // Each path tracks which lessons are completed
        html: { completed: [], progress: 0, startedAt: null },
        css: { completed: [], progress: 0, startedAt: null },
        js: { completed: [], progress: 0, startedAt: null },
        debugging: { completed: [], progress: 0, startedAt: null },
      },
      lessons: {}, // Individual lesson completion data | Format: { 'lesson-id': { completed: true, score: 100, attempts: 1, completedAt: ISO date } }
      challenges: {}, // Challenge completion data | Format: { 'challenge-id': { solved: true, solvedAt: ISO date } }
      streak: {
        current: 0, // Current consecutive days
        longest: 0, // Best streak ever
        lastActivityDate: null, // Last activity date (YYYY-MM-DD format)
        history: [], // Array of active dates for calendar view
      },
      badges: [], // Earned badges | Format: { id, name, earnedAt, icon }
      stats: {
        totalLessons: 0, // Total lessons completed
        totalChallenges: 0, // Total challenges solved
        totalTime: 0, // Total time spent (minutes)
        codeExecutions: 0, // Number of times code was run
        hintsUsed: 0, // Number of hints accessed
      },
    };
  }

  /**
   * Generate unique user ID
   * Uses timestamp + random string for uniqueness
   */
  generateUserId() {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Load progress from localStorage
   * Merges saved data with default structure to handle schema updates
   */
  loadProgress() {
    try {
      const saved = localStorage.getItem(this.storageKey);

      if (saved) {
        const parsed = JSON.parse(saved);

        // Merge with default to ensure all fields exist (handles schema updates)
        this.progress = this.deepMerge(this.getDefaultProgress(), parsed);

        // Update last active timestamp
        this.progress.user.lastActive = new Date().toISOString();

        // Update streak if needed
        this.updateStreak();

        console.log('📊 Progress loaded:', this.progress);
      } else {
        console.log('📊 No saved progress found, starting fresh');
      }
    } catch (error) {
      console.error('❌ Error loading progress:', error);
      // Keep default progress if load fails
    }
  }

  /**
   * Save progress to localStorage
   * Automatically called after any progress update
   */
  saveProgress() {
    try {
      this.progress.user.lastActive = new Date().toISOString();
      localStorage.setItem(this.storageKey, JSON.stringify(this.progress));
      console.log('💾 Progress saved');
    } catch (error) {
      console.error('❌ Error saving progress:', error);
    }
  }

  /**
   * Deep merge two objects
   * Used to merge saved progress with default structure
   */
  deepMerge(target, source) {
    const output = { ...target };

    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        output[key] = this.deepMerge(target[key] || {}, source[key]);
      } else {
        output[key] = source[key];
      }
    }

    return output;
  }

  /**
   * Mark a lesson as completed
   * Updates path progress, stats, badges, and saves
   */
  completeLesson(lessonId, pathId, score = 100) {
    console.log(`✅ Completing lesson: ${lessonId} (path: ${pathId})`);

    // Record lesson completion with details
    this.progress.lessons[lessonId] = {
      completed: true,
      score: score, // 0-100 score
      attempts: (this.progress.lessons[lessonId]?.attempts || 0) + 1,
      completedAt: new Date().toISOString(),
      pathId: pathId,
    };

    // Update path progress
    if (this.progress.paths[pathId]) {
      // Add to completed array if not already there
      if (!this.progress.paths[pathId].completed.includes(lessonId)) {
        this.progress.paths[pathId].completed.push(lessonId);
      }

      // Set started timestamp if first lesson
      if (!this.progress.paths[pathId].startedAt) {
        this.progress.paths[pathId].startedAt = new Date().toISOString();
      }

      // Calculate progress percentage (will be updated by tutorial engine with total lesson count)
      this.progress.paths[pathId].progress = this.progress.paths[pathId].completed.length;
    }

    // Increment total lessons stat
    this.progress.stats.totalLessons++;

    // Update streak
    this.updateStreak();

    // Check for badge unlocks
    this.checkBadges();

    // Save to localStorage
    this.saveProgress();

    // Trigger completion event for UI updates
    this.triggerEvent('lessonComplete', { lessonId, pathId, score });
  }

  /**
   * Mark a challenge as solved
   */
  solveChallenge(challengeId) {
    console.log(`🎯 Challenge solved: ${challengeId}`);

    this.progress.challenges[challengeId] = {
      solved: true,
      solvedAt: new Date().toISOString(),
    };

    this.progress.stats.totalChallenges++;
    this.checkBadges();
    this.saveProgress();
    this.triggerEvent('challengeSolved', { challengeId });
  }

  /**
   * Update streak based on activity
   * Checks if user was active today, increments streak if consecutive day
   */
  updateStreak() {
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
    const lastDate = this.progress.streak.lastActivityDate;

    // Check if already counted today
    if (lastDate === today) {
      return; // Already counted today's activity
    }

    // Calculate days difference
    if (lastDate) {
      const lastTimestamp = new Date(lastDate).getTime();
      const todayTimestamp = new Date(today).getTime();
      const daysDiff = Math.floor((todayTimestamp - lastTimestamp) / (1000 * 60 * 60 * 24));

      if (daysDiff === 1) {
        // Consecutive day - increment streak
        this.progress.streak.current++;
      } else if (daysDiff > 1) {
        // Streak broken - reset to 1
        this.progress.streak.current = 1;
      }
      // daysDiff === 0 means same day (shouldn't happen due to check above)
    } else {
      // First activity ever
      this.progress.streak.current = 1;
    }

    // Update longest streak if current exceeds it
    if (this.progress.streak.current > this.progress.streak.longest) {
      this.progress.streak.longest = this.progress.streak.current;
    }

    // Update last activity date
    this.progress.streak.lastActivityDate = today;

    // Add to history for calendar view
    if (!this.progress.streak.history.includes(today)) {
      this.progress.streak.history.push(today);
    }

    console.log(`🔥 Streak: ${this.progress.streak.current} days`);
  }

  /**
   * Check and award badges based on achievements
   * Badges are only awarded once
   */
  checkBadges() {
    const badges = [
      {
        id: 'first-lesson',
        name: 'First Steps',
        description: 'Complete your first lesson',
        icon: '🎯',
        condition: () => this.progress.stats.totalLessons >= 1,
      },
      {
        id: 'five-lessons',
        name: 'Getting Started',
        description: 'Complete 5 lessons',
        icon: '🌟',
        condition: () => this.progress.stats.totalLessons >= 5,
      },
      {
        id: 'path-complete',
        name: 'Path Master',
        description: 'Complete an entire learning path',
        icon: '🏆',
        condition: () => Object.values(this.progress.paths).some((p) => p.completed.length >= 5), // Assuming min 5 lessons per path
      },
      {
        id: 'week-streak',
        name: 'Dedicated Learner',
        description: '7 day streak',
        icon: '🔥',
        condition: () => this.progress.streak.current >= 7,
      },
      {
        id: 'month-streak',
        name: 'Unstoppable',
        description: '30 day streak',
        icon: '⚡',
        condition: () => this.progress.streak.current >= 30,
      },
      {
        id: 'challenge-master',
        name: 'Problem Solver',
        description: 'Solve 10 challenges',
        icon: '🧩',
        condition: () => this.progress.stats.totalChallenges >= 10,
      },
      {
        id: 'all-paths',
        name: 'Full Stack Beginner',
        description: 'Complete all learning paths',
        icon: '💎',
        condition: () => Object.values(this.progress.paths).every((p) => p.completed.length >= 4),
      },
    ];

    const earnedBadgeIds = this.progress.badges.map((b) => b.id);

    badges.forEach((badge) => {
      // Check if badge not already earned and condition is met
      if (!earnedBadgeIds.includes(badge.id) && badge.condition()) {
        this.awardBadge(badge);
      }
    });
  }

  /**
   * Award a badge to the user
   * Shows notification and updates progress
   */
  awardBadge(badge) {
    console.log(`🏅 Badge earned: ${badge.name}`);

    this.progress.badges.push({
      id: badge.id,
      name: badge.name,
      description: badge.description,
      icon: badge.icon,
      earnedAt: new Date().toISOString(),
    });

    this.saveProgress();
    this.triggerEvent('badgeEarned', badge);

    // Show notification (UI will handle display)
    this.showBadgeNotification(badge);
  }

  /**
   * Show badge notification (to be implemented by UI)
   */
  showBadgeNotification(badge) {
    // Dispatch custom event for UI to catch
    window.dispatchEvent(
      new CustomEvent('dvn-badge-earned', {
        detail: badge,
      })
    );
  }

  /**
   * Get current statistics for dashboard
   * Returns formatted stats object for UI display
   */
  getStats() {
    return {
      lessonsCompleted: this.progress.stats.totalLessons,
      challengesSolved: this.progress.stats.totalChallenges,
      dayStreak: this.progress.streak.current,
      longestStreak: this.progress.streak.longest,
      badges: this.progress.badges.length,
      totalLessons: 23, // Total available lessons (all paths combined)
      pathProgress: {
        html: this.getPathProgress('html'),
        css: this.getPathProgress('css'),
        js: this.getPathProgress('js'),
        debugging: this.getPathProgress('debugging'),
      },
    };
  }

  /**
   * Get progress percentage for a specific path
   */
  getPathProgress(pathId) {
    const pathData = this.progress.paths[pathId];
    if (!pathData) {
      return 0;
    }

    // Define total lessons per path (should match academy.js)
    const totalLessons = {
      html: 5,
      css: 6,
      js: 8,
      debugging: 4,
    };

    const completed = pathData.completed.length;
    const total = totalLessons[pathId] || 1;

    return Math.round((completed / total) * 100);
  }

  /**
   * Check if a lesson is completed
   */
  isLessonCompleted(lessonId) {
    return this.progress.lessons[lessonId]?.completed || false;
  }

  /**
   * Get lesson attempts count
   */
  getLessonAttempts(lessonId) {
    return this.progress.lessons[lessonId]?.attempts || 0;
  }

  /**
   * Record time spent on lessons
   */
  addTime(minutes) {
    this.progress.stats.totalTime += minutes;
    this.saveProgress();
  }

  /**
   * Increment code execution counter
   */
  incrementCodeExecutions() {
    this.progress.stats.codeExecutions++;
    this.saveProgress();
  }

  /**
   * Increment hints used counter
   */
  incrementHintsUsed() {
    this.progress.stats.hintsUsed++;
    this.saveProgress();
  }

  /**
   * Reset all progress (for testing or user request)
   */
  resetProgress() {
    if (confirm('⚠️ Are you sure you want to reset ALL progress? This cannot be undone!')) {
      this.progress = this.getDefaultProgress();
      this.saveProgress();
      console.log('🔄 Progress reset');
      window.location.reload(); // Reload page to reflect reset
    }
  }

  /**
   * Export progress as JSON (for backup)
   */
  exportProgress() {
    const dataStr = JSON.stringify(this.progress, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `dvn-academy-progress-${new Date().toISOString().split('T')[0]}.json`;
    link.click();

    console.log('📥 Progress exported');
  }

  /**
   * Import progress from JSON file (for restore)
   */
  importProgress(jsonData) {
    try {
      const imported = JSON.parse(jsonData);
      this.progress = this.deepMerge(this.getDefaultProgress(), imported);
      this.saveProgress();
      console.log('📤 Progress imported');
      window.location.reload();
    } catch (error) {
      console.error('❌ Error importing progress:', error);
      alert('Failed to import progress. Invalid file format.');
    }
  }

  /**
   * Trigger custom events for other components to listen
   */
  triggerEvent(eventName, data) {
    window.dispatchEvent(
      new CustomEvent(`dvn-${eventName}`, {
        detail: data,
      })
    );
  }
}

// Create global instance
window.ProgressTracker = new ProgressTracker();
