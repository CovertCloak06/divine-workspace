/**
 * Projects Module
 * Handles project management and project-related operations
 */

import { showToast, escapeHtml } from './utils.js';
import { loadProjectsFromStorage, saveProjectsToStorage } from './storage.js';

// Global state
let currentProjectId = null;
let currentChatId = null;

/**
 * Set current project ID
 * @param {string} projectId - The project ID to set
 */
export function setCurrentProjectId(projectId) {
    currentProjectId = projectId;
    window.currentProjectId = projectId;
}

/**
 * Get current project ID
 * @returns {string} Current project ID
 */
export function getCurrentProjectId() {
    return currentProjectId;
}

/**
 * Render the projects list in the sidebar
 */
export function renderProjects() {
    const projects = loadProjectsFromStorage();
    const projectsList = document.getElementById('projectsList');

    if (!projectsList) return;
    projectsList.innerHTML = '';

    projects.forEach(project => {
        const item = document.createElement('div');
        item.className = 'project-item' + (project.id === currentProjectId ? ' active' : '');
        item.dataset.projectId = project.id;

        const nameDiv = document.createElement('div');
        nameDiv.className = 'project-name';
        nameDiv.textContent = project.name;
        nameDiv.onclick = (e) => {
            e.stopPropagation();
            switchProject(project.id);
        };
        item.appendChild(nameDiv);

        const menuBtn = document.createElement('button');
        menuBtn.className = 'history-menu-btn';
        menuBtn.style.padding = '2px 4px';
        menuBtn.textContent = '⋮';
        menuBtn.onclick = (e) => {
            e.stopPropagation();
            openProjectMenu(project.id, menuBtn);
        };
        item.appendChild(menuBtn);

        projectsList.appendChild(item);
    });
}

/**
 * Switch to a different project
 * @param {string} projectId - The project ID to switch to
 */
export function switchProject(projectId) {
    const projects = loadProjectsFromStorage();
    const project = projects.find(p => p.id === projectId);
    if (!project) return;

    currentProjectId = projectId;
    window.currentProjectId = projectId;

    if (project.chats && project.chats.length > 0) {
        currentChatId = project.chats[0].id;
        window.currentChatId = currentChatId;
    } else {
        currentChatId = null;
        window.currentChatId = null;
    }

    const messagesContainer = document.getElementById('messagesContainer');
    if (messagesContainer) messagesContainer.innerHTML = '';

    if (currentChatId) {
        window.reloadCurrentChat && window.reloadCurrentChat();
    } else if (project.systemPrompt) {
        window.addMessage && window.addMessage('System Prompt: ' + project.systemPrompt, 'system', false);
    }

    renderProjects();
    window.renderHistory && window.renderHistory();
}

/**
 * Open project context menu
 * @param {string} projectId - The project ID
 * @param {HTMLElement} anchorButton - The button that triggered the menu
 */
export function openProjectMenu(projectId, anchorButton) {
    // Close any existing menu
    if (window.closeHistoryMenu) window.closeHistoryMenu();

    const rect = anchorButton.getBoundingClientRect();
    const containerRect = document.body.getBoundingClientRect();

    const menu = document.createElement('div');
    menu.className = 'history-menu';

    const openItem = document.createElement('div');
    openItem.className = 'history-menu-item';
    openItem.textContent = 'Open project';
    openItem.onclick = () => {
        switchProject(projectId);
        window.closeHistoryMenu && window.closeHistoryMenu();
    };
    menu.appendChild(openItem);

    const renameItem = document.createElement('div');
    renameItem.className = 'history-menu-item';
    renameItem.textContent = 'Rename project';
    renameItem.onclick = () => {
        const newName = prompt('Enter new project name:');
        if (newName && newName.trim()) {
            const projects = loadProjectsFromStorage();
            const project = projects.find(p => p.id === projectId);
            if (project) {
                project.name = newName.trim();
                saveProjectsToStorage(projects);
                renderProjects();
            }
        }
        window.closeHistoryMenu && window.closeHistoryMenu();
    };
    menu.appendChild(renameItem);

    const deleteItem = document.createElement('div');
    deleteItem.className = 'history-menu-item';
    deleteItem.textContent = 'Delete project';
    deleteItem.onclick = () => {
        if (confirm('Delete this project and all its chats?')) {
            let projects = loadProjectsFromStorage();
            projects = projects.filter(p => p.id !== projectId);
            saveProjectsToStorage(projects);
            if (currentProjectId === projectId) {
                currentProjectId = null;
                window.currentProjectId = null;
                currentChatId = null;
                window.currentChatId = null;
                const messagesContainer = document.getElementById('messagesContainer');
                if (messagesContainer) messagesContainer.innerHTML = '';
            }
            renderProjects();
            window.renderHistory && window.renderHistory();
        }
        window.closeHistoryMenu && window.closeHistoryMenu();
    };
    menu.appendChild(deleteItem);

    const top = rect.bottom - containerRect.top + window.scrollY;
    const left = rect.left - containerRect.left + window.scrollX;
    menu.style.top = top + 'px';
    menu.style.left = left + 'px';

    document.body.appendChild(menu);
    window.openMenuElement = menu;
}

/**
 * Create a new project
 */
export function createNewProject() {
    const modal = document.getElementById('projectModal');
    if (modal) {
        modal.style.display = 'flex';
        const nameInput = document.getElementById('projectName');
        const promptInput = document.getElementById('projectPrompt');
        const filesList = document.getElementById('projectFilesList');

        if (nameInput) nameInput.value = '';
        if (promptInput) promptInput.value = '';
        if (filesList) filesList.innerHTML = '';

        window.projectModalFiles = [];
    }
}

/**
 * Close the project modal
 */
export function closeProjectModal() {
    const modal = document.getElementById('projectModal');
    if (modal) modal.style.display = 'none';
}

/**
 * Save a new project
 */
export async function saveNewProject() {
    const name = document.getElementById('projectName')?.value.trim();
    const systemPrompt = document.getElementById('projectPrompt')?.value.trim();
    const files = window.projectModalFiles || [];

    if (!name) {
        alert('Please enter a project name.');
        return;
    }

    const projects = loadProjectsFromStorage();
    const projectId = 'project_' + Date.now();
    const chatId = 'chat_' + Date.now();

    // Upload project files to server
    const uploadedFiles = [];
    for (const file of files) {
        try {
            const fd = new FormData();
            fd.append('file', file);
            const resp = await fetch('/api/files/upload', { method: 'POST', body: fd });
            const j = await resp.json();
            if (resp.ok) {
                uploadedFiles.push({
                    id: j.id,
                    filename: j.filename,
                    storedName: j.stored_name,
                    size: file.size,
                    uploadedAt: Date.now()
                });
            }
        } catch (e) {
            console.error('File upload failed:', e);
        }
    }

    // Create first chat for the project
    const firstChat = {
        id: chatId,
        title: 'Project Chat',
        messages: [],
        starred: false,
        archived: false,
        useFullHistory: true,
        updatedAt: Date.now()
    };

    // Add system prompt as first message if provided
    if (systemPrompt) {
        firstChat.messages.push({
            id: 'msg_' + Date.now(),
            sender: 'system',
            text: 'System Prompt: ' + systemPrompt,
            timestamp: Date.now()
        });
    }

    projects.push({
        id: projectId,
        name: name,
        systemPrompt: systemPrompt,
        description: '',
        chats: [firstChat],
        files: uploadedFiles,
        images: [],
        createdAt: Date.now(),
        updatedAt: Date.now()
    });

    saveProjectsToStorage(projects);
    currentProjectId = projectId;
    window.currentProjectId = projectId;
    currentChatId = chatId;
    window.currentChatId = chatId;

    renderProjects();
    closeProjectModal();

    // Load the project's first chat
    const messagesContainer = document.getElementById('messagesContainer');
    if (messagesContainer) messagesContainer.innerHTML = '';

    if (systemPrompt && window.addMessage) {
        window.addMessage('System Prompt: ' + systemPrompt, 'system', false);
    }

    let msg = `Project "${name}" created`;
    if (uploadedFiles.length > 0) {
        msg += ` with ${uploadedFiles.length} file${uploadedFiles.length > 1 ? 's' : ''}`;
    }
    if (window.addMessage) {
        window.addMessage(msg + '.', 'system', false);
    }
}

/**
 * Show modal to move a chat to a project
 * @param {string} chatId - The chat ID to move
 */
export function showMoveToProjectModal(chatId) {
    const modal = document.getElementById('moveToProjectModal');
    const list = document.getElementById('moveToProjectList');

    if (!modal || !list) return;

    const projects = loadProjectsFromStorage();
    list.innerHTML = '';

    if (projects.length === 0) {
        list.innerHTML = '<p style="color: #999; text-align: center; padding: 20px;">No projects available. Create a project first.</p>';
    } else {
        projects.forEach(project => {
            const item = document.createElement('div');
            item.className = 'project-file-item';
            item.style.cursor = 'pointer';
            item.style.padding = '12px';
            item.style.marginBottom = '8px';
            item.style.border = '1px solid #333';
            item.style.borderRadius = '4px';
            item.style.transition = 'background 0.2s';
            item.innerHTML = `<strong>${escapeHtml(project.name)}</strong>`;
            if (project.description) {
                item.innerHTML += `<br><small style="color: #999;">${escapeHtml(project.description)}</small>`;
            }
            item.onmouseover = () => item.style.background = '#222';
            item.onmouseout = () => item.style.background = '';
            item.onclick = () => {
                moveChatToProject(chatId, project.id);
                closeMoveToProjectModal();
            };
            list.appendChild(item);
        });
    }

    modal.style.display = 'flex';
}

/**
 * Close the move to project modal
 */
export function closeMoveToProjectModal() {
    const modal = document.getElementById('moveToProjectModal');
    if (modal) modal.style.display = 'none';
}

/**
 * Move a chat to a project
 * @param {string} chatId - The chat ID to move
 * @param {string} projectId - The destination project ID
 */
export function moveChatToProject(chatId, projectId) {
    // Get the chat from global storage
    const { loadChatsFromStorage, saveChatsToStorage } = require('./storage.js');
    let chats = loadChatsFromStorage();
    const chatIndex = chats.findIndex(c => c.id === chatId);

    if (chatIndex === -1) {
        alert('Chat not found.');
        return;
    }

    const chat = chats[chatIndex];

    // Get the project
    const projects = loadProjectsFromStorage();
    const project = projects.find(p => p.id === projectId);

    if (!project) {
        alert('Project not found.');
        return;
    }

    // Move chat to project
    if (!project.chats) project.chats = [];
    project.chats.push(chat);
    project.updatedAt = Date.now();

    // Remove from global chats
    chats.splice(chatIndex, 1);

    // Save both
    saveChatsToStorage(chats);
    saveProjectsToStorage(projects);

    // Update UI
    window.renderHistory && window.renderHistory();
    renderProjects();

    showToast(`Chat moved to project "${project.name}"`, 3000, 'success');
}

/**
 * Load a project from data
 * @param {Object} projectData - Project data object
 */
export function loadProjectFromData(projectData) {
    if (!projectData || !projectData.id) return;

    const projects = loadProjectsFromStorage();
    const existingIndex = projects.findIndex(p => p.id === projectData.id);

    if (existingIndex >= 0) {
        projects[existingIndex] = projectData;
    } else {
        projects.push(projectData);
    }

    saveProjectsToStorage(projects);
    renderProjects();
}

// Export for backward compatibility
export { currentProjectId, currentChatId };
