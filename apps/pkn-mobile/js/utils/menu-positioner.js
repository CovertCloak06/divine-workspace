/**
 * Menu Positioning Utility
 * Fixes context menu positioning issues where menus appear too low
 * Ensures menus appear directly below their trigger buttons
 */

export class MenuPositioner {
    constructor() {
        this.activeMenu = null;
        this.menuOffset = 2; // Pixels below button
    }

    /**
     * Position a menu relative to a button element
     * @param {HTMLElement} menu - The menu element to position
     * @param {HTMLElement} button - The button that triggered the menu
     * @param {Object} options - Positioning options
     */
    positionMenu(menu, button, options = {}) {
        if (!menu || !button) {
            console.error('Menu positioner: Missing menu or button element');
            return;
        }

        const {
            offset = this.menuOffset,
            alignRight = false,
            alignBottom = false
        } = options;

        // Get button position relative to viewport
        const rect = button.getBoundingClientRect();

        // Calculate position
        let top, left;

        if (alignBottom) {
            // Menu appears above button (for bottom-positioned buttons)
            top = rect.top - menu.offsetHeight - offset;
        } else {
            // Menu appears below button (default)
            top = rect.bottom + offset;
        }

        if (alignRight) {
            // Align menu's right edge with button's right edge
            left = rect.right - menu.offsetWidth;
        } else {
            // Align menu's left edge with button's left edge (default)
            left = rect.left;
        }

        // Add scroll offsets
        top += window.scrollY;
        left += window.scrollX;

        // Ensure menu stays within viewport
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        // Adjust if menu goes off right edge
        if (left + menu.offsetWidth > viewportWidth) {
            left = viewportWidth - menu.offsetWidth - 10;
        }

        // Adjust if menu goes off left edge
        if (left < 10) {
            left = 10;
        }

        // Adjust if menu goes off bottom edge
        if (top + menu.offsetHeight > viewportHeight + window.scrollY) {
            // Position above button instead
            top = rect.top + window.scrollY - menu.offsetHeight - offset;
        }

        // Adjust if menu goes off top edge
        if (top < window.scrollY + 10) {
            top = window.scrollY + 10;
        }

        // Apply position
        menu.style.position = 'absolute';
        menu.style.top = `${top}px`;
        menu.style.left = `${left}px`;
        menu.style.zIndex = '9999';

        // Store reference
        this.activeMenu = menu;
    }

    /**
     * Close the currently active menu
     */
    closeActiveMenu() {
        if (this.activeMenu) {
            this.activeMenu.remove();
            this.activeMenu = null;
        }
    }

    /**
     * Setup click-outside-to-close handler
     */
    setupClickOutsideHandler() {
        document.addEventListener('click', (e) => {
            if (this.activeMenu && !this.activeMenu.contains(e.target)) {
                this.closeActiveMenu();
            }
        });
    }
}

// Create global instance
if (typeof window !== 'undefined') {
    window.menuPositioner = new MenuPositioner();
    window.menuPositioner.setupClickOutsideHandler();
}

export default MenuPositioner;
