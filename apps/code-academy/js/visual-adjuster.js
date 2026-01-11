/**
 * Visual Adjuster Component for DVN Code Academy
 * Tier 1 (Beginner) - Visual controls with +/- buttons and sliders
 */

class VisualAdjuster {
  constructor(taskData, taskArea, onComplete) {
    this.taskData = taskData;
    this.taskArea = taskArea;
    this.onComplete = onComplete;
    this.currentValues = {};
    this.previewElement = null;

    // Initialize current values from defaults
    taskData.controls.forEach((control) => {
      this.currentValues[control.property] = control.default;
    });

    this.render();
  }

  render() {
    this.taskArea.innerHTML = `
            <div class="visual-adjuster">
                <!-- Live Preview Area -->
                <div class="adjuster-preview" id="adjusterPreview">
                    ${this.renderPreview()}
                </div>

                <!-- Controls Panel -->
                <div class="adjuster-controls">
                    ${this.taskData.controls.map((control) => this.renderControl(control)).join('')}
                </div>

                <!-- Check Button -->
                <button id="checkAdjustment" class="btn-primary" style="margin-top: 20px; width: 100%;">
                    ✓ Check My Values
                </button>

                <!-- Feedback -->
                <div id="adjusterFeedback" class="task-feedback" style="margin-top: 15px;"></div>
            </div>
        `;

    // Attach event listeners
    this.attachListeners();
    this.updatePreview();
  }

  renderPreview() {
    const containerStyle = this.taskData.previewContainer || '';
    return `
            <div class="preview-container" style="${containerStyle}">
                <div id="livePreviewElement" class="preview-element">
                    ${this.taskData.previewElement}
                </div>
            </div>
        `;
  }

  renderControl(control) {
    const value = this.currentValues[control.property];
    const arrows = control.showArrows
      ? `
            <button class="arrow-btn up-btn" data-property="${control.property}">▲</button>
            <button class="arrow-btn down-btn" data-property="${control.property}">▼</button>
        `
      : '';

    return `
            <div class="adjuster-control" data-property="${control.property}">
                <div class="control-header">
                    <label>${control.label}</label>
                    <span class="control-value" id="value-${control.property}">
                        ${value}${control.unit}
                    </span>
                </div>

                <div class="control-inputs">
                    <button class="btn-adjust minus" data-property="${control.property}" data-action="minus">
                        −
                    </button>

                    <input
                        type="range"
                        class="control-slider"
                        data-property="${control.property}"
                        min="${control.min}"
                        max="${control.max}"
                        step="${control.step}"
                        value="${value}"
                    />

                    <button class="btn-adjust plus" data-property="${control.property}" data-action="plus">
                        +
                    </button>
                </div>

                ${arrows}
            </div>
        `;
  }

  attachListeners() {
    // Slider changes
    this.taskArea.querySelectorAll('.control-slider').forEach((slider) => {
      slider.addEventListener('input', (e) => {
        const property = e.target.dataset.property;
        const value = parseInt(e.target.value);
        this.updateValue(property, value);
      });
    });

    // Plus/Minus buttons
    this.taskArea.querySelectorAll('.btn-adjust').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const property = e.target.dataset.property;
        const action = e.target.dataset.action;
        const control = this.taskData.controls.find((c) => c.property === property);
        const currentValue = this.currentValues[property];

        let newValue = currentValue;
        if (action === 'plus') {
          newValue = Math.min(control.max, currentValue + control.step);
        } else if (action === 'minus') {
          newValue = Math.max(control.min, currentValue - control.step);
        }

        this.updateValue(property, newValue);

        // Update slider
        const slider = this.taskArea.querySelector(`input[data-property="${property}"]`);
        if (slider) {
          slider.value = newValue;
        }
      });
    });

    // Arrow buttons (for positioning)
    this.taskArea.querySelectorAll('.arrow-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const property = e.target.dataset.property;
        const control = this.taskData.controls.find((c) => c.property === property);
        const isUp = e.target.classList.contains('up-btn');
        const currentValue = this.currentValues[property];

        let newValue = currentValue;
        if (isUp) {
          newValue = Math.max(control.min, currentValue - control.step);
        } else {
          newValue = Math.min(control.max, currentValue + control.step);
        }

        this.updateValue(property, newValue);

        // Update slider
        const slider = this.taskArea.querySelector(`input[data-property="${property}"]`);
        if (slider) {
          slider.value = newValue;
        }
      });
    });

    // Check button
    document.getElementById('checkAdjustment')?.addEventListener('click', () => {
      this.checkValues();
    });
  }

  updateValue(property, value) {
    this.currentValues[property] = value;

    // Update display
    const valueDisplay = document.getElementById(`value-${property}`);
    const control = this.taskData.controls.find((c) => c.property === property);
    if (valueDisplay) {
      valueDisplay.textContent = `${value}${control.unit}`;
    }

    // Update preview
    this.updatePreview();
  }

  updatePreview() {
    const previewEl = document.querySelector('#livePreviewElement > *');
    if (!previewEl) {
      return;
    }

    // Apply all current values as inline styles
    const additionalStyles = this.taskData.additionalStyles || '';
    let styleString = additionalStyles;

    Object.entries(this.currentValues).forEach(([property, value]) => {
      const control = this.taskData.controls.find((c) => c.property === property);
      const cssProperty = property.replace(/([A-Z])/g, '-$1').toLowerCase();
      styleString += ` ${cssProperty}: ${value}${control.unit};`;
    });

    previewEl.style.cssText += styleString;
  }

  checkValues() {
    const feedback = document.getElementById('adjusterFeedback');
    let allCorrect = true;
    const incorrectProps = [];

    this.taskData.controls.forEach((control) => {
      const currentValue = this.currentValues[control.property];
      if (control.target && currentValue !== control.target) {
        allCorrect = false;
        incorrectProps.push({
          label: control.label,
          current: currentValue + control.unit,
          target: control.target + control.unit,
        });
      }
    });

    if (allCorrect) {
      feedback.innerHTML = `
                <div class="feedback-success">
                    ✓ Perfect! All values are correct. Click "Next" to continue.
                </div>
            `;
      this.onComplete(true);
    } else {
      feedback.innerHTML = `
                <div class="feedback-error">
                    ✗ Not quite right. Check these values:
                    <ul>
                        ${incorrectProps
                          .map(
                            (prop) =>
                              `<li>${prop.label}: You have ${prop.current}, need ${prop.target}</li>`
                          )
                          .join('')}
                    </ul>
                </div>
            `;
    }
  }
}

// Export for use in tutorial engine
window.VisualAdjuster = VisualAdjuster;
