/**
 * Lesson Loader Service
 * Handles loading lesson data from JSON files
 * Includes caching for performance
 */

class LessonLoader {
  constructor() {
    this.cache = new Map(); // Cache loaded lessons | Prevents redundant network requests
  }

  /**
   * Loads lesson data from JSON file
   * @param {Object} lessonMeta - Lesson metadata from path config
   * @param {string} lessonMeta.id - Unique lesson identifier
   * @param {string} lessonMeta.content - Path to lesson JSON file
   * @param {boolean} [forceRefresh=false] - Bypass cache if true
   * @returns {Promise<Object|null>} Lesson data or null if error
   * @example
   * const loader = new LessonLoader();
   * const lesson = await loader.loadLesson({
   *   id: 'html-01',
   *   content: 'lessons/html/lesson-01.json'
   * });
   */
  async loadLesson(lessonMeta, forceRefresh = false) {
    // Check cache first unless force refresh | Improves performance on lesson re-entry
    if (!forceRefresh && this.cache.has(lessonMeta.id)) {
      console.log(`📦 Loading lesson from cache: ${lessonMeta.id}`);
      return this.cache.get(lessonMeta.id);
    }

    try {
      const jsonPath = lessonMeta.content;

      if (!jsonPath) {
        throw new Error(`No content path specified for lesson: ${lessonMeta.id}`);
      }

      console.log(`🔄 Fetching lesson from: ${jsonPath}`);

      const response = await fetch(jsonPath);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const lessonData = await response.json();

      // Validate lesson data structure | ref:lessons/schemas/lesson-schema.json (when created)
      this.validateLessonData(lessonData);

      // Cache the loaded lesson
      this.cache.set(lessonMeta.id, lessonData);

      console.log(`✅ Loaded lesson: ${lessonMeta.id}`, lessonData);

      return lessonData;
    } catch (error) {
      console.error(`❌ Error loading lesson ${lessonMeta.id}:`, error);
      return null;
    }
  }

  /**
   * Validates lesson data structure
   * @param {Object} data - Lesson data to validate
   * @throws {Error} If validation fails
   * @private
   */
  validateLessonData(data) {
    // Basic validation (can be enhanced with Ajv schema validation later)
    if (!data.id) {
      throw new Error('Lesson missing required field: id');
    }

    if (!data.title) {
      throw new Error('Lesson missing required field: title');
    }

    if (!data.steps || !Array.isArray(data.steps)) {
      throw new Error('Lesson missing required field: steps (must be array)');
    }

    if (data.steps.length === 0) {
      throw new Error('Lesson must have at least one step');
    }

    // Validate each step has required fields
    data.steps.forEach((step, index) => {
      if (!step.title) {
        throw new Error(`Step ${index + 1} missing required field: title`);
      }

      if (!step.content) {
        throw new Error(`Step ${index + 1} missing required field: content`);
      }

      if (!step.task) {
        throw new Error(`Step ${index + 1} missing required field: task`);
      }

      if (!step.task.type) {
        throw new Error(`Step ${index + 1} task missing required field: type`);
      }
    });
  }

  /**
   * Clears lesson cache
   * @param {string} [lessonId] - Specific lesson to clear, or all if omitted
   */
  clearCache(lessonId) {
    if (lessonId) {
      this.cache.delete(lessonId);
      console.log(`🗑️ Cleared cache for lesson: ${lessonId}`);
    } else {
      this.cache.clear();
      console.log('🗑️ Cleared all lesson cache');
    }
  }

  /**
   * Preloads a list of lessons into cache
   * @param {Array<Object>} lessonMetas - Array of lesson metadata objects
   * @returns {Promise<void>}
   */
  async preloadLessons(lessonMetas) {
    console.log(`📥 Preloading ${lessonMetas.length} lessons...`);

    const promises = lessonMetas.map((meta) => this.loadLesson(meta));

    await Promise.all(promises);

    console.log('✅ Lessons preloaded');
  }

  /**
   * Gets cached lesson data without fetching
   * @param {string} lessonId - Lesson identifier
   * @returns {Object|null} Cached lesson data or null
   */
  getCached(lessonId) {
    return this.cache.get(lessonId) || null;
  }

  /**
   * Checks if lesson is cached
   * @param {string} lessonId - Lesson identifier
   * @returns {boolean} True if lesson is cached
   */
  isCached(lessonId) {
    return this.cache.has(lessonId);
  }
}

export default LessonLoader;
