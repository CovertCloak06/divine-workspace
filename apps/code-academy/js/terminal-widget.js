/**
 * Terminal Widget for DVN Code Academy
 * Small 1-2 line terminal display for showing commands in lessons
 * NOT a full terminal emulator - just visual representation
 */

class TerminalWidget {
  constructor(container, options = {}) {
    this.container = container;
    this.options = {
      prompt: options.prompt || 'student@dvn:~/projects$',
      animated: options.animated !== false,
      showPrompt: options.showPrompt !== false,
      height: options.height || 'auto', // 'auto', '1-line', '2-line'
      ...options,
    };

    this.history = [];
    this.render();
  }

  /**
   * Render terminal widget
   */
  render() {
    const heightClass = this.options.height === '1-line' ? 'terminal-widget-compact' : '';

    this.container.innerHTML = `
            <div class="terminal-widget ${heightClass}">
                <div class="terminal-header">
                    <div class="terminal-dots">
                        <span class="dot dot-red"></span>
                        <span class="dot dot-yellow"></span>
                        <span class="dot dot-green"></span>
                    </div>
                    <div class="terminal-title">Terminal</div>
                </div>
                <div class="terminal-body" id="terminalBody">
                    ${this.options.showPrompt ? `<div class="terminal-prompt">${this.options.prompt}</div>` : ''}
                </div>
            </div>
        `;

    this.bodyElement = this.container.querySelector('#terminalBody');
  }

  /**
   * Execute a command (show it in terminal)
   */
  async executeCommand(command, expectedResult = null) {
    // Add command line
    const cmdLine = document.createElement('div');
    cmdLine.className = 'terminal-line terminal-command';

    if (this.options.showPrompt) {
      cmdLine.innerHTML = `<span class="terminal-prompt">${this.options.prompt}</span> <span class="terminal-cmd-text">${this.escapeHtml(command)}</span>`;
    } else {
      cmdLine.innerHTML = `<span class="terminal-cmd-symbol">$</span> <span class="terminal-cmd-text">${this.escapeHtml(command)}</span>`;
    }

    this.bodyElement.appendChild(cmdLine);

    // Animate typing if enabled
    if (this.options.animated) {
      await this.typeCommand(cmdLine.querySelector('.terminal-cmd-text'), command);
    }

    // Show cursor while "executing"
    const cursor = document.createElement('span');
    cursor.className = 'terminal-cursor-blink';
    cursor.textContent = '▋';
    this.bodyElement.appendChild(cursor);

    // Simulate command execution delay
    await this.delay(this.options.animated ? 500 : 100);

    // Remove cursor
    cursor.remove();

    // Add result
    if (expectedResult) {
      const resultLine = document.createElement('div');
      resultLine.className = 'terminal-line terminal-result';
      resultLine.innerHTML = `<span class="terminal-result-icon">✓</span> ${this.escapeHtml(expectedResult)}`;
      this.bodyElement.appendChild(resultLine);

      // Fade in result
      if (this.options.animated) {
        resultLine.style.opacity = '0';
        requestAnimationFrame(() => {
          resultLine.style.transition = 'opacity 0.3s ease';
          resultLine.style.opacity = '1';
        });
      }
    }

    // Store in history
    this.history.push({ command, result: expectedResult });

    // Scroll to bottom
    this.bodyElement.scrollTop = this.bodyElement.scrollHeight;

    return true;
  }

  /**
   * Show error message
   */
  showError(message) {
    const errorLine = document.createElement('div');
    errorLine.className = 'terminal-line terminal-error';
    errorLine.innerHTML = `<span class="terminal-error-icon">✗</span> ${this.escapeHtml(message)}`;
    this.bodyElement.appendChild(errorLine);
    this.bodyElement.scrollTop = this.bodyElement.scrollHeight;
  }

  /**
   * Show info message (without command prompt)
   */
  showInfo(message) {
    const infoLine = document.createElement('div');
    infoLine.className = 'terminal-line terminal-info';
    infoLine.textContent = message;
    this.bodyElement.appendChild(infoLine);
    this.bodyElement.scrollTop = this.bodyElement.scrollHeight;
  }

  /**
   * Animate typing effect
   */
  async typeCommand(element, text) {
    element.textContent = '';
    const chars = text.split('');

    for (let i = 0; i < chars.length; i++) {
      element.textContent += chars[i];
      await this.delay(30 + Math.random() * 40); // Vary speed for realism
    }
  }

  /**
   * Clear terminal
   */
  clear() {
    this.bodyElement.innerHTML = '';
    if (this.options.showPrompt) {
      const promptLine = document.createElement('div');
      promptLine.className = 'terminal-prompt';
      promptLine.textContent = this.options.prompt;
      this.bodyElement.appendChild(promptLine);
    }
    this.history = [];
  }

  /**
   * Create interactive input (for user to type commands)
   */
  createInput(placeholder = 'Type command here...', onSubmit) {
    const inputLine = document.createElement('div');
    inputLine.className = 'terminal-line terminal-input-line';

    inputLine.innerHTML = `
            <span class="terminal-prompt">${this.options.prompt}</span>
            <input
                type="text"
                class="terminal-input"
                placeholder="${placeholder}"
                spellcheck="false"
                autocomplete="off"
            />
        `;

    const input = inputLine.querySelector('.terminal-input');

    // Submit on Enter
    input.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const command = input.value.trim();
        if (command) {
          // Replace input with static command
          inputLine.innerHTML = `<span class="terminal-prompt">${this.options.prompt}</span> <span class="terminal-cmd-text">${this.escapeHtml(command)}</span>`;

          // Call submit handler
          if (onSubmit) {
            const result = await onSubmit(command);
            if (result) {
              if (result.success) {
                const resultLine = document.createElement('div');
                resultLine.className = 'terminal-line terminal-result';
                resultLine.innerHTML = `<span class="terminal-result-icon">✓</span> ${this.escapeHtml(result.message)}`;
                this.bodyElement.appendChild(resultLine);
              } else {
                this.showError(result.message);
              }
            }
          }

          // Store in history
          this.history.push({ command, interactive: true });
        }
      }
    });

    this.bodyElement.appendChild(inputLine);
    input.focus();

    return input;
  }

  /**
   * Get command history
   */
  getHistory() {
    return this.history;
  }

  /**
   * Helper: Delay
   */
  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Helper: Escape HTML
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Export for use in lessons
window.TerminalWidget = TerminalWidget;
